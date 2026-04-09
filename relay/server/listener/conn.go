package listener

import (
	"context"
	"net"
)

// Conn is the relay connection contract implemented by WS and QUIC transports.
type Conn interface {
	Read(ctx context.Context, b []byte) (n int, err error)
	Write(ctx context.Context, b []byte) (n int, err error)
	RemoteAddr() net.Addr
	Close() error
}
