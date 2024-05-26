package ws

import (
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type Conn struct {
	*websocket.Conn
}

func NewConn(wsConn *websocket.Conn) net.Conn {
	return &Conn{
		wsConn,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	t, r, err := c.NextReader()
	if err != nil {
		return 0, err
	}

	if t != websocket.BinaryMessage {
		return 0, fmt.Errorf("unexpected message type")
	}

	return r.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, b)
	return len(b), err
}

func (c *Conn) SetDeadline(t time.Time) error {
	errR := c.SetReadDeadline(t)
	errW := c.SetWriteDeadline(t)

	if errR != nil {
		return errR
	}

	if errW != nil {
		return errW
	}
	return nil
}

func (c *Conn) Close() error {
	err := c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
	if err != nil {
		log.Errorf("failed to close conn?: %s", err)
	}
	return c.Conn.Close()
}
