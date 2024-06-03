package quic

import (
	"net"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type Conn struct {
	quic.Stream
	qConn quic.Connection
}

func NewConn(stream quic.Stream, qConn quic.Connection) net.Conn {
	return &Conn{
		Stream: stream,
		qConn:  qConn,
	}
}

func (q *Conn) Write(b []byte) (n int, err error) {
	log.Debugf("writing: %d, %x\n", len(b), b)
	n, err = q.Stream.Write(b)
	if n != len(b) {
		log.Errorf("failed to write out the full message")
	}
	return
}

func (q *Conn) Close() error {
	err := q.Stream.Close()
	if err != nil {
		log.Errorf("failed to close stream: %s", err)
		return err
	}
	err = q.qConn.CloseWithError(0, "")
	if err != nil {
		log.Errorf("failed to close connection: %s", err)
		return err

	}
	return err
}

func (c *Conn) LocalAddr() net.Addr {
	return c.qConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.qConn.RemoteAddr()
}
