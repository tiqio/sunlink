package httptunnel

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/klauspost/compress/gzhttp"
	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/log"
)

const RelayBufferSize = cipher.MaxCipherRelaySize
const DefaultConnCount = 256

type pushPayload struct {
	AccountID   string `faker:"uuid_hyphenated" json:"account_id"`
	AccessToken string `faker:"jwt" json:"access_token"`
	Payload     string `faker:"-" json:"payload"`
	RequestUID  string `faker:"-" json:"request_uid"`
}

type pullParam struct {
	AccountID     string `faker:"uuid_hyphenated" json:"account_id"`
	TransactionID string `faker:"uuid_hyphenated" json:"transaction_id"`
	AccessToken   string `faker:"jwt" json:"access_token"`
}

type pullResp struct {
	AccountID     string `faker:"uuid_hyphenated" json:"account_id"`
	TransactionID string `faker:"uuid_hyphenated" json:"transaction_id"`
	Payload       string `faker:"-" json:"payload"`
}

type Server struct {
	addr    string
	timeout time.Duration

	sync.RWMutex
	connMap map[string]*struct {
		conns              []net.Conn
		ch                 chan struct{}
		timer              *time.Timer
		isPushCloseRunning bool
	}
	connCh      chan net.Conn
	closing     chan struct{}
	pullWaiting map[string]chan struct{}
	tlsConfig   *tls.Config
	server      *http.Server
}

func NewServer(addr string, timeout time.Duration, tlsConfig *tls.Config) *Server {
	server := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: timeout,
	}

	return &Server{
		addr:    addr,
		timeout: timeout,
		connMap: make(map[string]*struct {
			conns              []net.Conn
			ch                 chan struct{}
			timer              *time.Timer
			isPushCloseRunning bool
		}),
		connCh:      make(chan net.Conn, 1),
		closing:     make(chan struct{}, 1),
		pullWaiting: make(map[string]chan struct{}, DefaultConnCount),
		tlsConfig:   tlsConfig,
		server:      server,
	}
}

// Listen s.server.Serve(netListener)
func (s *Server) Listen() {
	s.handler()

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Error("[HTTP_TUNNEL_SERVER] Listen", "err", err)
		os.Exit(1)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}

	log.Info("[HTTP_TUNNEL_SERVER] listen http tunnel at", "addr", s.addr)
	log.Warn("[HTTP_TUNNEL_SERVER] http server:", "err", s.server.Serve(ln))
}

func (s *Server) Close() error {
	s.Lock()
	defer s.Unlock()
	close(s.closing)

	return s.server.Close()
}

func (s *Server) Accept() (net.Conn, error) {
	select {
	case conn := <-s.connCh:
		return conn, nil
	case <-s.closing:
		return nil, errors.New("server is closed")
	}
}

func (s *Server) closeConn(reqID string) {
	if conns, ok := s.connMap[reqID]; ok {
		_ = conns.conns[0].Close()
	}

	s.connMap[reqID] = nil
	delete(s.connMap, reqID)
}

func (s *Server) handler() {
	http.Handle("GET /pull", gzhttp.GzipHandler(http.HandlerFunc(s.pull)))
	http.Handle("POST /push", gzhttp.GzipHandler(http.HandlerFunc(s.push)))
}

func writeNotFoundError(w http.ResponseWriter) {
	w.Header().Set("Content-Encoding", "gzip")
	http.Error(w, "404 NOT FOUND", http.StatusNotFound)
}

func writeServiceUnavailableError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Encoding", "gzip")
	http.Error(w, msg, http.StatusServiceUnavailable)
}

func writeSuccess(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	if _, err := w.Write([]byte(`{"code":"SUCCESS", "message":"PUSH SUCCESS"}`)); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] write success", "err", err)
	}
}
