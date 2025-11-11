package httptunnel

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-faker/faker/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/imroc/req/v3"
	"github.com/tiqio/sunlink/cipher"
	"github.com/tiqio/sunlink/log"
	"github.com/tiqio/sunlink/utils/bytespool"
	"github.com/tiqio/sunlink/utils/netpipe"
)

type Client struct {
	uuid       string
	serverAddr string
	serverName string
	conn       net.Conn
	conn2      net.Conn

	client   *req.Client
	respBody io.ReadCloser
	left     []byte
}

func NewClient(client *req.Client, serverAddr, serverName string) (net.Conn, error) {
	if client == nil {
		return nil, errors.New("http client is nil")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	conn, conn2 := netpipe.Pipe(2 * cipher.MaxPayloadSize)
	lc := &Client{
		uuid:       id.String(),
		serverAddr: serverAddr,
		serverName: serverName,
		conn:       conn,
		conn2:      conn2,
		client:     client,
	}

	go lc.Push()
	go lc.Pull()

	return conn, nil
}

func (c *Client) Push() {
	defer func() {
		_ = c.conn.(interface{ CloseWrite() error }).CloseWrite()
	}()
	if err := c.push(); err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, netpipe.ErrPipeClosed) &&
			!strings.Contains(err.Error(), "pipe closed") {
			log.Error("[HTTP_TUNNEL_LOCAL] push", "err", err, "uuid", c.uuid)
		}
	}

	log.Debug("[HTTP_TUNNEL_LOCAL] Push completed...", "uuid", c.uuid)
}

func (c *Client) push() error {
	r := c.client.R().
		SetHeader("Host", c.serverName).
		SetHeader("Content-Type", "application/json").
		SetHeader("Transfer-Encoding", "chunked").
		SetHeader("Accept-Encoding", "gzip").
		SetHeader("Content-Encoding", "gzip").
		SetQueryParam(RequestIDQuery, c.uuid)

	buf := bytespool.Get(cipher.MaxCipherRelaySize)
	defer bytespool.MustPut(buf)

	defer func() {
		// pushPayload is one end signal
		p := &pushPayload{RequestUID: c.uuid}
		_ = faker.FakeData(p)

		payload, _ := json.Marshal(p)
		resp, err := r.SetBody(payload).Post(c.serverAddr + "/push")
		if err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] push end", "err", err, "uuid", c.uuid)
			return
		}
		if _, err = resp.ToBytes(); err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] push end", "err", err, "uuid", c.uuid)
		}
	}()

	for {
		var resp *req.Response
		n, err1 := c.Read(buf)
		if n > 0 {
			var err2 error
			resp, err2 = r.SetBody(buf[:n]).Post(c.serverAddr + "/push")
			if err2 != nil {
				return errors.Join(err1, err2)
			}
		}
		if resp != nil {
			body, err3 := resp.ToBytes()
			if err3 != nil {
				return err3
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("status code: %v, body: %v", resp.StatusCode, string(body))
			}
		}
		if err1 != nil {
			return err1
		}
	}
}

// Read implements io.Reader
func (c *Client) Read(b []byte) (int, error) {
	if len(c.left) > 0 {
		cn := copy(b, c.left)
		if cn < len(c.left) {
			c.left = c.left[cn:]
		} else {
			c.left = nil
		}
		return cn, nil
	}

	buf := bytespool.Get(cipher.MaxPayloadSize)
	defer bytespool.MustPut(buf)

	var payload []byte
	n, err := c.conn2.Read(buf)
	if n > 0 {
		p := &pushPayload{}
		_ = faker.FakeData(p)
		p.Payload = base64.StdEncoding.EncodeToString(buf[:n])
		p.RequestUID = l.uuid
		payload, _ = json.Marshal(p)
	}

	cn := copy(b, payload)
	if cn < len(payload) {
		c.left = payload[cn:]
	}

	return cn, err
}

func (c *Client) Pull() {
	if c.respBody == nil {
		if err := c.pull(); err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] pull", "err", err, "uuid", c.uuid)
			return
		}
	}
	defer c.PullClose()

	buffer := bufio.NewReaderSize(c.respBody, cipher.MaxCipherRelaySize)
	var resp pullResp
	for {
		buf, err := buffer.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
				!strings.Contains(err.Error(), "connection reset by peer") &&
				!strings.Contains(err.Error(), "use of closed network connection") {
				log.Warn("[HTTP_TUNNEL_LOCAL] decode response", "err", err, "uuid", c.uuid)
			}
		}

		if len(buf) == 0 {
			break
		}

		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] unmarshal response", "err", err, "uuid", c.uuid)
			break
		}
		if resp.Payload == "" {
			break
		}

		data, err := base64.StdEncoding.DecodeString(resp.Payload)
		if err != nil {
			log.Error("[HTTP_TUNNEL_LOCAL] decode cipher text", "err", err, "uuid", c.uuid)
			break
		}
		resp.Payload = ""
		if _, err := c.conn2.Write(data); err != nil {
			if !errors.Is(err, netpipe.ErrPipeClosed) {
				log.Error("[HTTP_TUNNEL_LOCAL] write text", "err", err, "uuid", c.uuid)
			}
			break
		}
	}
	log.Debug("[HTTP_TUNNEL_LOCAL] Pull completed...", "uuid", c.uuid)
}

func (c *Client) pull() error {
	p := &pullParam{}
	if err := faker.FakeData(p); err != nil {
		return err
	}

	resp, err := c.client.R().
		SetQueryParam("account_id", p.AccountID).
		SetQueryParam("transaction_id", p.TransactionID).
		SetQueryParam("access_token", p.AccessToken).
		SetQueryParam(RequestIDQuery, c.uuid).
		SetHeader("Host", c.serverName).
		SetHeader("Accept-Encoding", "gzip").
		Get(c.serverAddr + "/pull")
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull response status code: %v, body: %v", resp.StatusCode, string(body))
	}

	c.respBody = resp.Body
	return nil
}

func (c *Client) PullClose() {
	if c.respBody != nil {
		_ = c.respBody.Close()
	}
	_ = c.conn2.(interface{ CloseWrite() error }).CloseWrite()
}
