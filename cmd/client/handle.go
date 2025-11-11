package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/httptunnel"
	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/bytespool"
	"github.com/tiqio/sunlink/utils/common"
	"github.com/txthinking/socks5"
)

func (ci *ClientInstance) handshakeWithRemote(addr string, flag uint8) (net.Conn, error) {
	stream, err := ci.AvailableConn()
	if err != nil {
		log.Error("[TCP_PROXY] get stream failed", "err", err)
		return nil, err
	}

	csStream, err := func() (*cipher.CipherStream, error) {
		cs, err := cipher.New(stream, ci.Password, cipher.MethodAes256GCM, cipher.FrameTypeData, flag)
		csStream := cs.(*cipher.CipherStream)
		if err != nil {
			log.Error("[TCP_PROXY] new cipherstream", "err", err)
			return csStream, err
		}

		cipherMethod := EncodeCipherMethod(ci.Method)
		frame := cipher.NewFrame(cipher.FrameTypeData, append([]byte(addr), cipherMethod), flag, csStream.AEADCipher)
		if err := csStream.WriteFrame(frame); err != nil {
			return csStream, err
		}

		return csStream, nil
	}()

	if err != nil {
		return csStream, err
	}
	csStream.Release()

	return cipher.New(stream, ci.Password, ci.Method, cipher.FrameTypeData, flag)
}

func (ci *ClientInstance) AvailableConn(needPingACK ...bool) (conn net.Conn, err error) {
	// test if ping is available
	pingTest := func(conn net.Conn) (er error) {
		var csStream net.Conn
		csStream, er = cipher.New(conn, ci.Password, cipher.MethodAes256GCM, cipher.FrameTypePing)
		if er != nil {
			return er
		}

		cs := csStream.(*cipher.CipherStream)
		defer func() {
			if er != nil {
				_ = conn.Close()
			}
			cs.Release()
		}()

		start := time.Now()
		ping := []byte(strconv.FormatInt(start.UnixNano(), 10))
		flag := cipher.FlagDefault
		if len(needPingACK) > 0 && needPingACK[0] {
			flag |= cipher.FlagNeedACK
		}
		if er = cs.WritePing(ping, flag); er != nil {
			return
		}

		return
	}

	ci.mu.RLock()
	defer ci.mu.RUnlock()
	conn, err = httptunnel.NewClient(ci.HTTPClient, "https://"+fmt.Sprintf("%s:%d", ci.ServerAddr, ci.ServerPort), ci.ServerAddr)
	err = pingTest(conn)
	if err != nil {
		log.Error("[LOCAL] ping-server", "err", err)
	}

	return
}

func MatchHostRule(host string) common.HostRule {
	return common.HostRuleDirect
}

func (ci *ClientInstance) TCPHandle(s *socks5.Server, conn *net.TCPConn, r *socks5.Request) error {
	targetAddr := r.Address()
	log.Debug("[SOCKS5]", "target", targetAddr, "is_udp", r.Cmd == socks5.CmdUDP)

	if r.Cmd == socks5.CmdConnect {
		a, addr, port, err := socks5.ParseAddress(conn.LocalAddr().String())
		if err != nil {
			log.Error("[SOCKS5] socks5 ParseAddress", "err", err)
			return err
		}
		p := socks5.NewReply(socks5.RepSuccess, a, addr, port)
		if _, err := p.WriteTo(conn); err != nil {
			return err
		}

		err, isRelay := common.IsTCPRelay(conn, targetAddr, ci.Timeout(), MatchHostRule)
		if err != nil {
			log.Error("[SOCKS5] failed to judge relay information")
			return err
		}

		if isRelay {
			csStream, err := ci.handshakeWithRemote(targetAddr, cipher.FlagTCP)
			if err != nil {
				log.Warn("[TCP_PROXY] handshake with remote server", "err", err)
				if csStream != nil {
					csStream.Close()
				}
				return err
			}
			defer csStream.Close()

			n1, n2, err := common.RemoteRelay(csStream, conn, ci.Timeout())
			ci.BytesSend.Add(n1)
			ci.BytesReceive.Add(n2)

			return nil
		}
	}

	if r.Cmd == socks5.CmdUDP {
		// as same port as tcp
		uaddr, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
		caddr, err := r.UDP(conn, uaddr)
		if err != nil {
			return err
		}

		// if client udp addr isn't private ip, we don't manage this conn
		if caddr.(*net.UDPAddr).IP.IsLoopback() || caddr.(*net.UDPAddr).IP.IsPrivate() ||
			caddr.(*net.UDPAddr).IP.IsUnspecified() {
			ch := make(chan struct{}, 2)
			portStr := strconv.FormatInt(int64(caddr.(*net.UDPAddr).Port), 10)
			// tcp record for udp handler
			s.AssociatedUDP.Set(portStr, ch, -1)
			defer func() {
				log.Debug("[SOCKS5] exit associate tcp connection, closing chan")
				ch <- struct{}{}
				s.AssociatedUDP.Delete(portStr)
			}()
		}

		_, _ = io.Copy(io.Discard, conn)
		log.Debug("[SOCKS5] a tcp connection that udp associated closed", "udp_addr", caddr.String(), "target_addr", targetAddr)

		return nil
	}

	return socks5.ErrUnsupportCmd
}

func (ci *ClientInstance) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	log.Debug("[SOCKS5_UDP] enter udp handle", "local_addr", addr.String(), "remote_addr", d.Address())

	dst := d.Address()
	rewrittenDst := dst

	msg := &dns.Msg{}
	err := msg.Unpack(d.Data)
	isDNSReq := isDNSRequest(msg)
	if err == nil && isDNSReq {
		question := msg.Question[0]

		rule := MatchHostRule(strings.TrimSuffix(question.Name, "."))
		if rule == common.HostRuleBlock {
			return responseBlockedDNSMsg(s.UDPConn, addr, msg, d.Address())
		}

		isDirect := rule == common.HostRuleDirect

		// find from dns cache first
		msgCache := ci.DNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
		if msgCache != nil {
			msgCache.MsgHdr.Id = msg.MsgHdr.Id
			log.Info("[DNS_CACHE] find from cache", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])
			if err := responseDNSMsg(s.UDPConn, addr, msgCache, d.Address()); err != nil {
				log.Error("[DNS_CACHE] write msg back", "err", err)
				return err
			}
			log.Debug("[DNS_CACHE] renew cache for", "domain", question.Name)
			ci.RenewDNSCache(question.Name, dns.TypeToString[question.Qtype], isDirect)
			return nil
		}

		if isDirect {
			log.Info("[DIRECT]", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])
			return ci.directUDPRelay(s, addr, d, true)
		}

		log.Info("[DNS_PROXY]", "domain", question.Name, "qtype", dns.TypeToString[question.Qtype])

		log.Debug("[DNS_PROXY] rewrite dns dst to", "server", DefaultProxyDNSServer)
		rewrittenDst = DefaultProxyDNSServer
	}

	dstHost, _, _ := net.SplitHostPort(rewrittenDst)
	if MatchHostRule(dstHost) == common.HostRuleDirect {
		return ci.directUDPRelay(s, addr, d, false)
	}

	var ch chan struct{}
	var hasAssoc bool

	portStr := strconv.FormatInt(int64(addr.Port), 10)
	asCh, ok := s.AssociatedUDP.Get(portStr)
	if ok {
		hasAssoc = true
		ch = asCh.(chan struct{})
		log.Debug("[UDP_PROXY] found the associate with tcp", "src", addr.String(), "dst", d.Address())
	} else {
		ch = make(chan struct{}, 2)
		log.Debug("[UDP_PROXY] the addr doesn't associate with tcp", "addr", addr.String(), "dst", d.Address())
	}

	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("the tcp that udp address %s associated closed", ue.ClientAddr.String())
		default:
		}
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}
		log.Debug("[UDP_PROXY] sent data to remote", "from", ue.ClientAddr.String())
		return nil
	}

	var ue *UDPExchange
	var exchKey = addr.String() + dst
	common.LockKey(exchKey)
	defer common.UnlockKey(exchKey)

	iue, ok := s.UDPExchanges.Get(exchKey)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	flag := cipher.FlagUDP
	if isDNSReq {
		flag |= cipher.FlagDNS
	}
	csStream, err := ci.handshakeWithRemote(rewrittenDst, flag)
	if err != nil {
		log.Error("[UDP_PROXY] handshake with remote server", "err", err)
		if csStream != nil {
			_ = csStream.Close()
		}
		return err
	}

	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: csStream,
	}
	if err := send(ue, d.Data); err != nil {
		_ = ue.RemoteConn.Close()
		return err
	}

	s.UDPExchanges.Set(exchKey, ue, -1)

	go func(ue *UDPExchange, dst string) {
		defer func() {
			common.LockKey(exchKey)
			defer common.UnlockKey(exchKey)
			ch <- struct{}{}
			s.UDPExchanges.Delete(exchKey)
		}()

		var buf = bytespool.Get(MaxUDPDataSize)
		defer bytespool.MustPut(buf)
		for {
			select {
			case <-ch:
				log.Info("[UDP_PROXY] the tcp that udp address associated closed", "udp_addr", ue.ClientAddr.String())
				return
			default:
			}

			if !hasAssoc {
				var err error
				if isDNSReq {
					err = ue.RemoteConn.SetDeadline(time.Now().Add(DefaultDNSTimeout))
				} else {
					err = ue.RemoteConn.SetReadDeadline(time.Now().Add(ci.Timeout()))
				}
				if err != nil {
					if !errors.Is(err, cipher.ErrTimeout) {
						log.Debug("[UDP_PROXY] remote conn read", "err", err)
					}
					return
				}
			}

			n, err := ue.RemoteConn.Read(buf[:])
			if err != nil {
				if !errors.Is(err, cipher.ErrTimeout) {
					log.Debug("[UDP_PROXY] remote conn read", "err", err)
				}
				return
			}

			log.Debug("[UDP_PROXY] got data from remote", "client", ue.ClientAddr.String(), "data_len", len(buf[0:n]))

			// if is dns response, set result to dns cache
			_msg := ci.SetDNSCacheIfNeeded(buf[0:n], false)

			a, addr, port, err := socks5.ParseAddress(dst)
			if err != nil {
				log.Error("[UDP_PROXY] parse dst address", "err", err)
				return
			}
			data := buf[0:n]
			if _msg != nil {
				data, _ = msg.Pack()
			}
			d1 := socks5.NewDatagram(a, addr, port, data)
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				return
			}
		}
	}(ue, dst)

	return nil
}

func isDNSRequest(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) == 0 {
		return false
	}
	q := msg.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		return true
	}
	return false
}

func responseBlockedDNSMsg(conn *net.UDPConn, localAddr *net.UDPAddr, request *dns.Msg, remoteAddr string) error {
	question := request.Question[0]
	log.Info("[DNS_BLOCK]", "domain", question.Name)

	m := new(dns.Msg)
	m.SetReply(request)
	if question.Qtype == dns.TypeA {
		rr, err := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", question.Name))
		if err != nil {
			log.Error("[DNS_BLOCK] creating A record:", "err", err)
			return err
		}
		m.Answer = append(m.Answer, rr)
	} else if question.Qtype == dns.TypeAAAA {
		rr, err := dns.NewRR(fmt.Sprintf("%s AAAA ::1", question.Name))
		if err != nil {
			log.Error("[DNS_BLOCK] creating AAAA record:", "err", err)
			return err
		}
		m.Answer = append(m.Answer, rr)
	}
	if err := responseDNSMsg(conn, localAddr, m, remoteAddr); err != nil {
		log.Error("[DNS_BLOCK] response", "err", err)
		return err
	}

	return nil
}

func responseDNSMsg(conn *net.UDPConn, localAddr *net.UDPAddr, msg *dns.Msg, remoteAddr string) error {
	a, _addr, port, _ := socks5.ParseAddress(remoteAddr)
	pack, _ := msg.Pack()
	d1 := socks5.NewDatagram(a, _addr, port, pack)

	_, err := conn.WriteToUDP(d1.Bytes(), localAddr)
	return err
}

func EncodeCipherMethod(m string) byte {
	switch m {
	case "aes-256-gcm":
		return 1
	case "chacha20-poly1305":
		return 2
	default:
		return 0
	}
}
