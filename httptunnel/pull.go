package httptunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/bytespool"
	"github.com/tiqio/sunlink/utils/netpipe"
)

const (
	RequestIDHeader = "X-Request-UID"
	RequestIDQuery  = "request_uid"
)

// pull conn -> http
func (s *Server) pull(w http.ResponseWriter, r *http.Request) {
	reqID := r.URL.Query().Get(RequestIDQuery)
	if reqID == "" {
		reqID = r.Header.Get(RequestIDHeader)
	}
	if reqID == "" {
		log.Warn("[HTTP_TUNNEL_SERVEr] pull uuid is empty")
		writeNotFoundError(w)
		return
	}

	if err := s.pullWait(reqID); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] pull uuid not found", "uuid", reqID)
		writeNotFoundError(w)
		return
	}

	s.RLock()
	conns := s.connMap[reqID].conns
	s.RUnlock()
	log.Debug("[HTTP_TUNNEL_SERVER] pull", "uuid", reqID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Content-Encoding", "gzip")

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	var n int
	var p = &pullResp{}
	for {
		_ = conns[0].SetReadDeadline(time.Now().Add(s.timeout))
		n, err = conns[0].Read(buf)
		if n > 0 {
			_ = faker.FakeData(p)
			p.Payload = base64.StdEncoding.EncodeToString(buf[:n])
			b, _ := json.Marshal(p)
			if _, er := w.Write(b); er != nil {
				err = errors.Join(err, er)
				log.Warn("[HTTP_TUNNEL_SERVER] response write", "err", er)
				break
			}
			_, _ = w.Write([]byte("\n"))
			p.Payload = ""
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, netpipe.ErrPipeClosed) {
		log.Warn("[HTTP_TUNNEL_SERVER] read from conn", "err", err)
	}

	s.pullCloseConn(reqID)
	log.Info("[HTTP_TUNNEL_SERVER] Pull completed...", "uuid", reqID)
}

// pullWait waiting ch in connMap
func (s *Server) pullWait(reqID string) error {
	s.Lock()
	if _, ok := s.connMap[reqID]; ok {
		s.Unlock()
		return nil
	}
	ch := make(chan struct{}, 1)
	s.pullWaiting[reqID] = ch
	s.Unlock()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		return errors.New("timeout for pull waiting")
	}

}

func (s *Server) pullCloseConn(reqID string) {
	s.Lock()
	defer s.Unlock()

	if conns, ok := s.connMap[reqID]; ok {
		close(conns.ch)
	}

	s.closeConn(reqID)
}
