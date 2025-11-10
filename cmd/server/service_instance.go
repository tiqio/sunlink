package main

import (
	"crypto/tls"
	"strconv"
	"sync"
	"time"

	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/httptunnel"
	"github.com/tiqio/sunlink/log"
)

type Conf struct {
	CertPath       string
	KeyPath        string
	HTTPTunnelAddr string
	Timeout        int
	Password       string
}

type ServerInstance struct {
	Conf
	tlsConfig        *tls.Config
	mu               sync.Mutex
	httpTunnelServer *httptunnel.Server
}

type OptionFunc func(conf *Conf)

func WithServerCert(certPath string, keyPath string) OptionFunc {
	return func(c *Conf) {
		c.CertPath = certPath
		c.KeyPath = keyPath
	}
}

func WithHTTPTunnelPort(HTTPTunnelPort int) OptionFunc {
	return func(c *Conf) {
		addr := "127.0.0.1:" + strconv.Itoa(HTTPTunnelPort)
		c.HTTPTunnelAddr = addr
	}
}

func WithTimeout(timeout int) OptionFunc {
	return func(c *Conf) {
		c.Timeout = timeout
	}
}

func WithPassword(password string) OptionFunc {
	return func(c *Conf) {
		c.Password = password
	}
}

func NewServerInstance(opts ...OptionFunc) *ServerInstance {
	conf := &defaultConf
	for _, opt := range opts {
		opt(conf)
	}
	log.Info("New Server Instance:", conf)
	return &ServerInstance{
		Conf: *conf,
	}
}

func (si *ServerInstance) initTLSConfig() error {
	var tlsConfig *tls.Config
	var err error
	if si.CertPath != "" && si.KeyPath != "" {
		log.Info("[REMOTE] using self-signed cert", "cert_path", si.CertPath, "key_path", si.KeyPath)
		var cer tls.Certificate
		if cer, err = tls.LoadX509KeyPair(si.CertPath, si.KeyPath); err != nil {
			return err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
	} else {
		// certmagic可以通过ACME协议自动申请一个证书（ACME是一种用于自动化管理SSL/TLS证书的协议，通常和Let's Encrypt一起使用）
		log.Error("[REMOTE] cert path or key path is empty")
		return nil
	}

	tlsConfig.CipherSuites = cipher.TLSCipherSuites
	tlsConfig.NextProtos = []string{"http/1.1", "h2", "h3"}
	si.tlsConfig = tlsConfig

	return nil
}

func (si *ServerInstance) Timeout() time.Duration {
	return time.Duration(si.Conf.Timeout) * time.Second
}

func (si *ServerInstance) MaxConnWaitTimeout() time.Duration {
	return 10 * time.Duration(si.Conf.Timeout) * time.Second
}

func (si *ServerInstance) startHTTPTunnelServer() {
	server := httptunnel.NewServer(si.HTTPTunnelAddr, si.MaxConnWaitTimeout(), si.tlsConfig.Clone())
	si.mu.Lock()
	si.httpTunnelServer = server
	si.mu.Unlock()

	go server.Listen()

	for {
		// handle conn2 after pushing
		conn, err := server.Accept()
		if err != nil {
			log.Error("[REMOTE] http tunnel server accept:", "err", err)
			break
		}
		log.Info("[REMOTE] a http tunnel connection is accepted", "remote_addr", conn.RemoteAddr().String())

		go si.handleConn(conn)
	}
}

var defaultConf = Conf{
	CertPath:       "",
	KeyPath:        "",
	HTTPTunnelAddr: "127.0.0.1:3080",
	Timeout:        10,
	Password:       "ddplus",
}
