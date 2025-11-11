package common

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiqio/sunlink/log"
)

func IsTCPRelay(localConn net.Conn, addr string, timeout time.Duration, f MatchFunc) (err error, isRelay bool) {
	host, _, _ := net.SplitHostPort(addr)
	rule := f(host)
	if rule == HostRuleBlock {
		log.Info("[TCP_BLOCK] blocked", "host", host)
		return err, false
	}

	if rule == HostRuleDirect {
		return directTCPRelay(localConn, addr, timeout), false
	}

	log.Info("[TCP_PROXY]", "target", addr)
	return nil, true
}

func directTCPRelay(localConn net.Conn, addr string, timeout time.Duration) error {
	log.Info("[TCP_DIRECT]", "target", addr)

	tConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		log.Warn("[TCP_DIRECT]", "dial", addr, "err", err)
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	wg.Go(func() {
		_, er := io.Copy(tConn, localConn)
		if er != nil && !ErrorCanIgnore(er) {
			err = errors.Join(err, er)
			log.Warn("[TCP_DIRECT] copy from local to remote", "err", er)
		}

		if er := CloseWrite(tConn); er != nil {
			err = errors.Join(err, er)
			log.Warn("[TCP_DIRECT] close write for target connection", "err", er)
		}

		if er = tConn.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
			err = errors.Join(err, er)
		}
	})

	wg.Go(func() {
		_, er := io.Copy(localConn, tConn)
		if er != nil && !ErrorCanIgnore(er) {
			log.Warn("[TCP_DIRECT] copy from remote to local", "err", err)
		}

		if er := CloseWrite(localConn); er != nil {
			log.Warn("[TCP_DIRECT] close write for local connection", "err", err)
		}

		if er = localConn.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
			err = errors.Join(err, er)
		}
	})

	return err
}
