package quic

import (
	"net"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type QuicConn struct {
	quic.Stream
	qConn quic.Connection
}

func NewConn(stream quic.Stream, qConn quic.Connection) net.Conn {
	return &QuicConn{
		Stream: stream,
		qConn:  qConn,
	}
}

func (q QuicConn) Write(b []byte) (n int, err error) {
	n, err = q.Stream.Write(b)
	if n != len(b) {
		log.Errorf("failed to write out the full message")
	}
	return
}

func (q QuicConn) LocalAddr() net.Addr {
	return q.qConn.LocalAddr()
}

func (q QuicConn) RemoteAddr() net.Addr {
	return q.qConn.RemoteAddr()
}
