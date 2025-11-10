package main

import (
	"io"
	"net"
	"strconv"

	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/common"
	"github.com/txthinking/socks5"
)

func (ci *ClientInstance) handshakeWithRemote(addr string, flag uint8) (net.Conn, error) {

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

		err, isRelay := common.IsRelay(conn, targetAddr, ci.Timeout(), MatchHostRule)
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

}
