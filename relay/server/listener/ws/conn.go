package ws

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type Conn struct {
	*websocket.Conn

	mu sync.Mutex
}

func NewConn(wsConn *websocket.Conn) *Conn {
	return &Conn{
		Conn: wsConn,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	t, r, err := c.NextReader()
	if err != nil {
		return 0, ioErrHandling(err)
	}

	if t != websocket.BinaryMessage {
		log.Errorf("unexpected message type: %d", t)
		return 0, fmt.Errorf("unexpected message type")
	}

	n, err = r.Read(b)
	if err != nil {
		return 0, ioErrHandling(err)
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	err := c.WriteMessage(websocket.BinaryMessage, b)
	c.mu.Unlock()
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

func ioErrHandling(err error) error {
	var wErr *websocket.CloseError
	if !errors.As(err, &wErr) {
		return err
	}
	if wErr.Code == websocket.CloseNormalClosure {
		return io.EOF
	}
	return err
}
