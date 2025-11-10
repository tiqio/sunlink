package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/bytespool"
	"github.com/tiqio/sunlink/utils/common"
	"github.com/tiqio/sunlink/utils/netpipe"
)

const MaxUDPDataSize = 65507

type hsRes struct {
	addr        []byte
	method      string
	frameHeader *cipher.Header
}

func (si *ServerInstance) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		res, err := si.handShakeWithClient(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debug("[REMOTE] got EOF error when handshake with client-server")
			} else if !errors.Is(err, netpipe.ErrReadDeadline) && !errors.Is(err, netpipe.ErrPipeClosed) {
				log.Warn("[REMOTE] handshake with client", "err", err)
			}
			return
		}

		// get remote addr
		addrStr := string(res.addr)
		log.Info("[REMOTE]", "target", addrStr)

		switch {
		case res.frameHeader.IsTCPProto():
			if err := si.remoteTCPHandle(conn, addrStr, res.method); err != nil {
				if !errors.Is(err, netpipe.ErrPipeClosed) {
					log.Warn("[REMOTE] tcp handle", "err", err)
					return
				}
			}
		case res.frameHeader.IsUDPProto():
			if err := si.remoteUDPHandle(conn, addrStr, res.method, res.frameHeader.IsDNSProto()); err != nil {
				if !errors.Is(err, netpipe.ErrPipeClosed) {
					log.Warn("[REMOTE] udp handle", "err", err)
					return
				}
			}
		default:
			log.Error("[REMOTE] unsupported proto_type")
			return
		}
	}
}

func (si *ServerInstance) handShakeWithClient(conn net.Conn) (hsRes, error) {
	res := hsRes{}
	csStream, err := cipher.New(conn, si.Conf.Password, cipher.MethodAes256GCM, cipher.FrameTypeUnknown)
	if err != nil {
		return res, err
	}
	cs := csStream.(*cipher.CipherStream)

	_ = csStream.SetReadDeadline(time.Now().Add(si.MaxConnWaitTimeout()))
	defer func() {
		_ = csStream.SetReadDeadline(time.Time{})
		cs.Release()
	}()

	var frame *cipher.Frame
	for {
		frame, err = cs.ReadFrame()
		if err != nil {
			return res, err
		}

		_ = csStream.SetReadDeadline(time.Now().Add(si.MaxConnWaitTimeout()))

		if frame.IsPingFrame() {
			log.Debug("[REMOTE] got ping message", "payload", string(frame.RawDataPayload()), "is_need_ack", frame.IsNeedACK())
			if frame.IsNeedACK() {
				if er := cs.WritePing(frame.RawDataPayload(), cipher.FlagACK); er != nil {
					return res, er
				}
			}
			continue
		}
		break
	}
	res.frameHeader = frame.Header

	rawData := frame.RawDataPayload()
	length := len(rawData)
	if length <= 1 {
		return res, errors.New("handshake: payload length is invalid")
	}
	res.method = DecodeCipherMethod(rawData[length-1])
	res.addr = rawData[:length-1]

	return res, nil
}

func (si *ServerInstance) remoteTCPHandle(conn net.Conn, addrStr, method string) error {
	tConn, err := net.DialTimeout("tcp", addrStr, si.Timeout())
	if err != nil {
		return fmt.Errorf("net.DialTCP %v err: %v", addrStr, err)
	}
	defer tConn.Close()

	csStream, err := cipher.New(conn, si.Password, method, cipher.FrameTypeData, cipher.FlagTCP)
	if err != nil {
		return fmt.Errorf("new cipherstream err: %v, method: %v", err, method)
	}

	n1, n2, err := common.RemoteRelay(csStream, tConn, si.Timeout())
	csStream.(*cipher.CipherStream).Release()

	log.Debug("[REMOTE] send bytes to, and receive bytes", "send_bytes", n2, "to", addrStr, "receive", n1)

	return err
}

func (si *ServerInstance) remoteUDPHandle(conn net.Conn, addrStr, method string, isDNSProto bool) error {
	uConn, err := net.DialTimeout("udp", addrStr, si.Timeout())
	if err != nil {
		return fmt.Errorf("net.DialUDP %v err: %v", addrStr, err)
	}

	csStream, err := cipher.New(conn, si.Password, method, cipher.FrameTypeData, cipher.FlagUDP)
	if err != nil {
		return fmt.Errorf("new cipherstream err: %v, method: %v", err, method)
	}

	defer func() {
		_ = csStream.SetDeadline(time.Time{})
		csStream.(*cipher.CipherStream).Release()
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)
	wg.Go(func() {
		var buf = bytespool.Get(MaxUDPDataSize)
		defer bytespool.MustPut(buf)
		for {
			n, err := csStream.Read(buf[:])
			if err != nil {
				if errors.Is(err, cipher.ErrFINRSTStream) {
					// can reuse conn when receive FIN
					log.Debug("[REMOTE_UDP] received FIN when reading data from client")
				} else if !errors.Is(err, io.EOF) && !errors.Is(err, netpipe.ErrReadDeadline) && !errors.Is(err, netpipe.ErrPipeClosed) {
					log.Warn("[REMOTE_UDP] read data from client connection", "err", err)
				}

				uConn.Close()
				return
			}

			if isDNSProto {
				// rey to parse the dns request
				msg := &dns.Msg{}
				if err := msg.Unpack(buf[:n]); err == nil {
					log.Info("[REMOTE_UDP] doing dns request for", "target", msg.Question[0].Name)
				}
			}
			_, err = uConn.Write(buf[:n])
			if err != nil {
				log.Error("[REMOTE_UDP] write data to remote connection", "err", err)
				return
			}
			_ = csStream.SetDeadline(time.Now().Add(si.MaxConnWaitTimeout()))
		}
	})

	wg.Go(func() {
		var buf = bytespool.Get(MaxUDPDataSize)
		defer bytespool.MustPut(buf)
		for {
			n, err := uConn.Read(buf[:])
			if err != nil {
				log.Debug("[REMOTE_UDP] read data from remote connection", "err", err)
				return
			}
			_, err = csStream.Write(buf[:n])
			if err != nil {
				log.Error("[REMOTE_UDP] write data to tcp connection", "err", err)
				return
			}
			_ = csStream.SetDeadline(time.Now().Add(si.MaxConnWaitTimeout()))
		}
	})

	return nil
}

func DecodeCipherMethod(b byte) string {
	methodMap := map[byte]string{
		1: cipher.MethodAes256GCM,
		2: cipher.MethodChaCha20Poly1305,
	}
	if m, ok := methodMap[b]; ok {
		return m
	}
	return ""
}
