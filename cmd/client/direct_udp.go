package main

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/bytespool"
	"github.com/tiqio/sunlink/utils/common"
	"github.com/txthinking/socks5"
)

// DirectUDPExchange used to store client address and remote connection
type DirectUDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.PacketConn
}

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

func (ci *ClientInstance) directUDPRelay(s *socks5.Server, laddr *net.UDPAddr, d *socks5.Datagram, isDNSReq bool) error {
	logPrefix := "[UDP_DIRECT]"
	if isDNSReq {
		logPrefix = "[DNS_DIRECT]"
	}

	var ch chan struct{}
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(laddr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan struct{})
		log.Debug(logPrefix+" found the associate with tcp", "src", laddr.String(), "dst", d.Address())
	} else {
		log.Debug(logPrefix+" the udp addr doesn't associate with tcp", logPrefix, "udp_addr", laddr.String(), "dst_addr", d.Address())
	}

	dst := d.Address()
	rewrittenDst := dst
	if isDNSReq {
		rewrittenDst = DefaultDirectDNSServer
	}
	log.Info(logPrefix, "target", rewrittenDst)

	uAddr, _ := net.ResolveUDPAddr("udp", rewrittenDst)

	send := func(ue *DirectUDPExchange, data []byte, addr net.Addr) error {
		select {
		case <-ch:
			// if ch is closed
			return fmt.Errorf("this udp address %s is not associated with tcp", ue.ClientAddr.String())
		default:
			// if ch is not closed, data is used from RemoteConn to addr
			_, err := ue.RemoteConn.WriteTo(data, addr)
			if err != nil {
				return err
			}
			log.Debug(logPrefix+" send data", "from", ue.ClientAddr.String(), "to", addr.String())
		}

		return nil
	}

	var ue *DirectUDPExchange
	var src = laddr.String()
	var exchKey = src + dst + DirectSuffix
	common.LockKey(exchKey)
	defer common.UnlockKey(exchKey)

	// socks5.Server.UDPExchanges?
	iue, ok := s.UDPExchanges.Get(exchKey)
	if ok {
		ue = iue.(*DirectUDPExchange)
		return send(ue, d.Data, uAddr)
	}

	// start one local conn pc for uAddr data sending
	pc, err := ci.directDialer.ListenPacket("tcp", "")
	if err != nil {
		log.Error(logPrefix+" listen packet", "err", err)
		return err
	}

	ue = &DirectUDPExchange{
		ClientAddr: laddr,
		RemoteConn: pc,
	}
	if err := send(ue, d.Data, uAddr); err != nil {
		log.Warn(logPrefix+" send data", "to", uAddr.String(), "err", err)
		return err
	}
	s.UDPExchanges.Set(exchKey, ue, -1)

	go func() {
		var buf = bytespool.Get(MaxUDPDataSize)
		defer func() {
			common.LockKey(exchKey)
			defer common.UnlockKey(exchKey)
			bytespool.MustPut(buf)
			s.UDPExchanges.Delete(exchKey)
			ue.RemoteConn.Close()
		}()

		for {
			select {
			case <-ch:
				log.Info(logPrefix+" the tcp that udp address associated closed", "udp_address", ue.ClientAddr.String())
				return
			default:
			}
			if !hasAssoc {
				var err error
				if isDNSReq {
					err = ue.RemoteConn.SetDeadline(time.Now().Add(DefaultDNSTimeout))
				} else {
					err = ue.RemoteConn.SetDeadline(time.Now().Add(ci.Timeout()))
				}
				if err != nil {
					log.Error(logPrefix+" set the deadline for remote conn", "err", err)
					return
				}
			}

			n, _, err := ue.RemoteConn.ReadFrom(buf)
			if err != nil {
				return
			}
			log.Debug(logPrefix+" got data from remote", "client", ue.ClientAddr.String(), "data_len", len(buf[0:n]))

			// if is dns response, set result to dns cache
			_msg := ci.SetDNSCacheIfNeeded(buf[0:n], true)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Error(logPrefix+" parse dst address", "err", err)
				return
			}
			data := buf[0:n]
			if _msg != nil {
				data, _ = _msg.Pack()
			}
			d1 := socks5.NewDatagram(a, addr, port, data)
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), laddr); err != nil {
				return
			}
		}
	}()

	return nil
}
