package httptunnel

import (
	"errors"
	"io"
	"net"

	"github.com/gofrs/uuid/v5"
	"github.com/imroc/req/v3"
	"github.com/tiqio/sunlink/cipher"
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
		serverAddr: serverName,
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

}

func (c *Client) Pull() {

}
