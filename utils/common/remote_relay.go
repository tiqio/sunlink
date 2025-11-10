package common

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/tiqio/sunlink/log"
)

type closeWriter interface {
	CloseWrite() error
}

type res struct {
	N   int64
	err error
}

// RemoteRelay copies between cipher stream and plaintext stream
func RemoteRelay(cipher, plainTxt net.Conn, timeout time.Duration) (int64, int64, error) {
	ch1 := make(chan res, 1)
	ch2 := make(chan res, 1)
	go copyCipherToPlainTxt(plainTxt, cipher, timeout, ch2)
	go copyPlainTxtToCipher(cipher, plainTxt, timeout, ch1)

	var res1, res2 res
	var n1, n2 int64
	var err error
	for i := 0; i < 2; i++ {
		select {
		case res1 = <-ch1:
			n1 = res1.N
			err = errors.Join(err, res1.err)
		case res2 = <-ch2:
			n2 = res2.N
			err = errors.Join(err, res2.err)
		}
	}

	return n1, n2, err
}

func copyCipherToPlainTxt(plainTxt, cipher net.Conn, timeout time.Duration, ch chan res) {
	var err error
	n, er := io.Copy(plainTxt, cipher)
	if er != nil {
		err = errors.Join(err, er)
		log.Debug("[REPLY] copy from cipher to plaintxt", "err", er)
	}

	if er := CloseWrite(plainTxt); er != nil {
		err = errors.Join(err, er)
		log.Warn("[REPLY] close write for plaintxt stream", "err", er)
	}

	if er = plainTxt.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
		err = errors.Join(err, er)
	}

	ch <- res{N: n, err: err}
}

func copyPlainTxtToCipher(cipher, plainTxt net.Conn, timeout time.Duration, ch chan res) {
	var err error
	n, er := io.Copy(cipher, plainTxt)
	if er != nil {
		err = errors.Join(err, er)
		log.Debug("[RELAY] copy from plaintxt to cipher", "err", er)
	}

	if er := CloseWrite(cipher); er != nil {
		err = errors.Join(err, er)
		log.Warn("[REPLY] close write for cipher stream", "err", er)
	}

	if er = cipher.SetReadDeadline(time.Now().Add(3 * timeout)); er != nil {
		err = errors.Join(err, er)
	}

	ch <- res{N: n, err: err}
}

func ErrorCanIgnore(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true /* ignore I/O timeout */
	}
	if errors.Is(err, syscall.EPIPE) {
		return true /* ignore broken pipe */
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true /* ignore connection reset by peer */
	}
	if errors.Is(err, syscall.ENOTCONN) {
		return true /* ignore transport endpoint is not connected */
	}
	if errors.Is(err, syscall.ESHUTDOWN) {
		return true /* ignore transport endpoint shutdown */
	}

	return false
}

func CloseWrite(conn net.Conn) error {
	var err error
	if cw, ok := conn.(closeWriter); ok {
		if err = cw.CloseWrite(); err != nil && ErrorCanIgnore(err) {
			return nil
		}
	}
	return err
}
