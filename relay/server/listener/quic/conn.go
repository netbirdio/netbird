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

func (q Conn) Write(b []byte) (n int, err error) {
	n, err = q.Stream.Write(b)
	if n != len(b) {
		log.Errorf("failed to write out the full message")
	}
	return
}

func (q Conn) LocalAddr() net.Addr {
	return q.qConn.LocalAddr()
}

func (q Conn) RemoteAddr() net.Addr {
	return q.qConn.RemoteAddr()
}
