package server

import (
	"context"
	"net"
	"testing"
)

// fakeConn is a minimal listener.Conn used to exercise transport-dependent Peer behavior.
type fakeConn struct {
	proto string
}

func (f fakeConn) Read(context.Context, []byte) (int, error)  { return 0, nil }
func (f fakeConn) Write(context.Context, []byte) (int, error) { return 0, nil }
func (f fakeConn) RemoteAddr() net.Addr                       { return nil }
func (f fakeConn) Close() error                               { return nil }
func (f fakeConn) Protocol() string                           { return f.proto }

func TestPeerTransport(t *testing.T) {
	for _, proto := range []string{"ws", "quic"} {
		p := &Peer{conn: fakeConn{proto: proto}}
		if got := p.Transport(); got != proto {
			t.Errorf("Transport() = %q, want %q", got, proto)
		}
	}
}
