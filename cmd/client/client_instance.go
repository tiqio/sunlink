package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/coocood/freecache"
	"github.com/imroc/req/v3"
	"github.com/klauspost/compress/gzhttp"
	utls "github.com/refraction-networking/utls"
	"github.com/tiqio/sunlink/utils/common"
	"github.com/txthinking/socks5"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
	"go.uber.org/atomic"

	"github.com/tiqio/sunlink/log"
)

const (
	UserAgent     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
	MaxIdle   int = 5

	// DefaultDNSCacheSize set default dns cache size to 2MB
	DefaultDNSCacheSize = 2 * 1024 * 1024
	// DefaultDNSCacheSec the default expire time for dns cache
	DefaultDNSCacheSec = 2 * 60 * 60

	DefaultProxyDNSServer  = "8.8.8.8:53"
	DefaultDirectDNSServer = "119.29.29.29:53"

	MaxUDPDataSize    = 65507
	DirectSuffix      = "direct"
	DefaultDNSTimeout = 5 * time.Second
)

type Conf struct {
	CertPath   string
	ServerAddr string
	ServerPort int
	SocksAddr  string
	Timeout    int
	Password   string
	Method     string
}

type ClientInstance struct {
	Conf
	tlsConfig  *utls.Config
	mu         sync.RWMutex
	HTTPClient *req.Client

	socksServer  *socks5.Server
	BytesSend    atomic.Int64
	BytesReceive atomic.Int64

	dnsCache       *freecache.Cache
	directDNSCache *freecache.Cache

	// used for direct tcp and udp connection
	directDialer *dialer.Dialer
}

type OptionFunc func(conf *Conf)

func WithCertPath(path string) OptionFunc {
	return func(c *Conf) {
		c.CertPath = path
	}
}

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

func WithMethod(method string) OptionFunc {
	return func(c *Conf) {
		c.Method = method
	}
}

func WithClientInstance(opts ...OptionFunc) *ClientInstance {
	conf := &defaultConf
	for _, opt := range opts {
		opt(conf)
	}
	log.Info("New Client Instance:", conf)

	return &ClientInstance{
		Conf:           *conf,
		dnsCache:       freecache.NewCache(DefaultDNSCacheSize),
		directDNSCache: freecache.NewCache(DefaultDNSCacheSize),
	}
}

func (ci *ClientInstance) initTLSConfig() error {
	if ci.CertPath == "" {
		return nil
	}
	e, err := common.FileExists(ci.CertPath)
	if err != nil {
		log.Error("[LOCAL] lookup self-signed ca cert", "err", err)
		return nil
	}
	if !e {
		log.Error("[LOCAL] ca cert is set but not exists, so self-signed cert is no effect", "cert_path", ci.CertPath)
		return nil
	} else {
		log.Info("[LOCAL] using self-signed", "cert_path", ci.CertPath)
		caBuf, err := os.ReadFile(ci.CertPath)
		if err != nil {
			log.Error("[LOCAL] failed to read cert", "cert_path", ci.CertPath)
			return nil
		}

		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil
		}
		if ok := certPool.AppendCertsFromPEM([]byte(caBuf)); !ok {
			log.Error("[LOCAL] append certs from pem failed")
			return nil
		}

		ci.mu.Lock()
		ci.tlsConfig = &utls.Config{
			ServerName: ci.ServerAddr,
			RootCAs:    certPool,
			NextProtos: []string{"http/1.1"},
		}
		defer ci.mu.Unlock()

		return nil
	}
}

func (ci *ClientInstance) initHTTPClient() error {
	client := req.C().
		EnableForceHTTP1().
		SetTimeout(0).
		DisableAutoReadResponse().
		SetUserAgent(UserAgent)
	client.
		SetMaxIdleConns(MaxIdle).
		SetIdleConnTimeout(ci.MaxLifeTime()).
		SetMaxConnsPerHost(512).
		SetTLSHandshakeTimeout(ci.TLSTimeout())
	client.
		GetTransport().
		WrapRoundTripFunc(func(rt http.RoundTripper) req.HttpRoundTripFunc {
			return func(req *http.Request) (resp *http.Response, err error) {
				resp, err = gzhttp.Transport(rt).RoundTrip(req)
				return
			}
		})

	client.SetDialTLS(func(_ context.Context, _, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), ci.Timeout())
		defer cancel()

		// mind this, this is not right, must use tun2socks api? (directRelay)
		tConn, err := ci.directDialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ci.ServerAddr, ci.ServerPort))
		if err != nil {
			return nil, err
		}

		uConn := utls.UClient(tConn, ci.tlsConfig.Clone(), utls.Hello360_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uConn, nil
	})

	client.SetProxy(nil)

	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.HTTPClient = client

	return nil
}

func (ci *ClientInstance) initDirectDialer() error {
	_, dev, err := common.SysGatewayAndDevice()
	if err != nil {
		log.Error("[INIT] failed to get direct Dialer", "err", err)
		return err
	}
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		log.Error("[INIT] failed to get name from dev", "err", err)
		return err
	}
	ci.directDialer = &dialer.Dialer{
		InterfaceName:  atomic.NewString(dev),
		InterfaceIndex: atomic.NewInt32(int32(iface.Index)),
		RoutingMark:    atomic.NewInt32(0),
	}
	return nil
}

func (ci *ClientInstance) Timeout() time.Duration {
	return time.Duration(ci.Conf.Timeout) * time.Second
}

func (ci *ClientInstance) MaxLifeTime() time.Duration {
	return 5 * ci.Timeout()
}

func (ci *ClientInstance) TLSTimeout() time.Duration {
	timeout := ci.Timeout() / 3
	if timeout < time.Second {
		timeout = time.Second
	}
	return timeout
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
	CertPath:   "",
	ServerAddr: "",
	ServerPort: 3080,
	SocksAddr:  "127.0.0.1:2080",
	Timeout:    10,
	Password:   "ddplus",
	Method:     "aes-256-gcm",
}
