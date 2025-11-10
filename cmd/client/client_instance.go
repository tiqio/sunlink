package main

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/txthinking/socks5"

	"github.com/tiqio/sunlink/log"
)

type Conf struct {
	ServerAddr string
	ServerPort int
	SocksAddr  string
	Timeout    int
	Password   string
}

type ClientInstance struct {
	Conf
	mu           sync.Mutex
	socksServer  *socks5.Server
	BytesSend    atomic.Int64
	BytesReceive atomic.Int64
}

type OptionFunc func(conf *Conf)

func WithServerAddr(addr string, port int) OptionFunc {
	return func(c *Conf) {
		c.ServerAddr = addr
		c.ServerPort = port
	}
}

func WithSocksPort(SocksPort int) OptionFunc {
	return func(c *Conf) {
		addr := "127.0.0.1:" + strconv.Itoa(SocksPort)
		c.SocksAddr = addr
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

func WithClientInstance(opts ...OptionFunc) *ClientInstance {
	conf := &defaultConf
	for _, opt := range opts {
		opt(conf)
	}
	log.Info("New Client Instance:", conf)
	return &ClientInstance{
		Conf: *conf,
	}
}

func (ci *ClientInstance) Timeout() time.Duration {
	return time.Duration(ci.Conf.Timeout) * time.Second
}

func (ci *ClientInstance) MaxConnWaitTimeout() time.Duration {
	return 10 * time.Duration(ci.Conf.Timeout) * time.Second
}

func (ci *ClientInstance) startSocksServer() {
	server, err := socks5.NewClassicServer(ci.SocksAddr, "127.0.0.1", "", "", 0, 0)
	if err != nil {
		log.Error("[SOCKS5] new socks5 server", "err", err)
		return
	}

	ci.mu.Lock()
	ci.socksServer = server
	ci.mu.Unlock()

	if err := server.ListenAndServe(ci); err != nil {
		log.Warn("[SOCKS5] local socks5 server")
	}
}

var defaultConf = Conf{
	ServerAddr: "",
	ServerPort: 3080,
	SocksAddr:  "127.0.0.1:2080",
	Timeout:    10,
	Password:   "ddplus",
}
