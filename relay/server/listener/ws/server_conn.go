package ws

import (
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type Conn struct {
	*websocket.Conn
}

func NewConn(wsConn *websocket.Conn) *Conn {
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
		log.Errorf("unexpected message type: %d", t)
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
