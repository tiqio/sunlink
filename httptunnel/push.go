package httptunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/bytespool"
	"github.com/tiqio/sunlink/utils/netpipe"
)

// push http -> conn, push -> pull
func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	buf := bytespool.GetBuffer()
	defer bytespool.PutBuffer(buf)

	_, err := io.Copy(buf, r.Body)
	if err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] read request body", "err", err, "body", buf.String())
		writeServiceUnavailableError(w, "read request body:"+err.Error())
		return
	}

	p := &pushPayload{}
	if err := json.Unmarshal(buf.Bytes(), p); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] unmarshal request body", "err", err, "body", buf.String())
		writeServiceUnavailableError(w, "unmarshal request body:"+err.Error())
		return
	}

	reqID := p.RequestUID
	if reqID == "" {
		reqID = r.Header.Get(RequestIDHeader)
	}
	if reqID == "" {
		log.Warn("[HTTP_TUNNEL_SERVER] push uuid is empty")
		writeNotFoundError(w)
		return
	}

	addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	s.Lock()
	conns, ok := s.connMap[reqID]
	if !ok {
		// conn1, conn2?
		conn1, conn2 := netpipe.Pipe(2*cipher.MaxPayloadSize, addr)
		conns = &struct {
			conns              []net.Conn
			ch                 chan struct{}
			timer              *time.Timer
			isPushCloseRunning bool
		}{
			conns: []net.Conn{conn1, conn2},
			ch:    make(chan struct{}, 1),
			timer: time.NewTimer(s.timeout),
		}
		s.connMap[reqID] = conns
		s.connCh <- conn2
	}
	s.notifyPull(reqID)
	s.Unlock()

	defer func() {
		s.Lock()
		defer s.Unlock()

		conns, ok := s.connMap[reqID]
		if !ok {
			return
		}
		timer := conns.timer
		timer.Reset(s.timeout)
		if conns.isPushCloseRunning {
			return
		}
		conns.isPushCloseRunning = true
		go s.pushCloseConn(reqID)
	}()

	if p.Payload == "" {
		_ = conns.conns[0].(interface{ CloseWrite() error }).CloseWrite()
		return
	}
	payload, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] decode cipher", "err", err)
		writeServiceUnavailableError(w, "decode cipher:"+err.Error())
		return
	}

	if _, err = conns.conns[0].Write(payload); err != nil {
		if !errors.Is(err, netpipe.ErrPipeClosed) {
			log.Warn("[HTTP_TUNNEL_SERVER] write local", "err", err)
			writeServiceUnavailableError(w, "write local:"+err.Error())
			return
		}
	}

	writeSuccess(w)
}

func (s *Server) notifyPull(reqID string) {
	ch, ok := s.pullWaiting[reqID]
	if !ok {
		return
	}
	ch <- struct{}{}

	s.pullWaiting[reqID] = nil
	delete(s.pullWaiting, reqID)
}

func (s *Server) pushCloseConn(reqID string) {
	s.RLock()
	conns, ok := s.connMap[reqID]
	if !ok {
		s.RUnlock()
		return
	}

	timer := conns.timer
	ch := conns.ch
	s.RUnlock()

	select {
	case <-s.closing:
	case <-timer.C:
	case <-ch:
	}

	s.Lock()
	defer s.Unlock()
	s.closeConn(reqID)
}
