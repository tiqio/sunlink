package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/common"
)

func (ci *ClientInstance) isTCPRelay(localConn net.Conn, addr string, timeout time.Duration, f common.MatchFunc) (err error, isRelay bool) {
	host, _, _ := net.SplitHostPort(addr)
	rule := f(host)
	if rule == common.HostRuleBlock {
		log.Info("[TCP_BLOCK] blocked", "host", host)
		return err, false
	}

	if rule == common.HostRuleDirect {
		return ci.directTCPRelay(localConn, addr, timeout), false
	}

	log.Info("[TCP_PROXY]", "target", addr)
	return nil, true
}

func (ci *ClientInstance) directTCPRelay(localConn net.Conn, addr string, timeout time.Duration) error {
	log.Info("[TCP_DIRECT]", "target", addr)

	ctx, cancel := context.WithTimeout(context.Background(), ci.Timeout())
	defer cancel()
	tConn, err := ci.directDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Warn("[TCP_DIRECT]", "dial", addr, "err", err)
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	wg.Go(func() {
		_, er := io.Copy(tConn, localConn)
		if er != nil && !common.ErrorCanIgnore(er) {
			err = errors.Join(err, er)
			log.Warn("[TCP_DIRECT] copy from local to remote", "err", er)
		}

		if er := common.CloseWrite(tConn); er != nil {
			err = errors.Join(err, er)
			log.Warn("[TCP_DIRECT] close write for target connection", "err", er)
		}

		if er = tConn.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
			err = errors.Join(err, er)
		}
	})

	wg.Go(func() {
		_, er := io.Copy(localConn, tConn)
		if er != nil && !common.ErrorCanIgnore(er) {
			log.Warn("[TCP_DIRECT] copy from remote to local", "err", err)
		}

		if er := common.CloseWrite(localConn); er != nil {
			log.Warn("[TCP_DIRECT] close write for local connection", "err", err)
		}

		if er = localConn.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
			err = errors.Join(err, er)
		}
	})

	return err
}
