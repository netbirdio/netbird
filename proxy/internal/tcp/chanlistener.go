package tcp

import (
	"net"
	"sync"
)

// chanListener implements net.Listener by reading connections from a channel.
// It allows the SNI router to feed HTTP connections to http.Server.ServeTLS.
type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

func newChanListener(ch chan net.Conn, addr net.Addr) *chanListener {
	return &chanListener{
		ch:     ch,
		addr:   addr,
		closed: make(chan struct{}),
	}
}

// Accept waits for and returns the next connection from the channel.
func (l *chanListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn, ok := <-l.ch:
			if !ok {
				return nil, net.ErrClosed
			}
			return conn, nil
		case <-l.closed:
			// Drain buffered connections before returning.
			for {
				select {
				case conn, ok := <-l.ch:
					if !ok {
						return nil, net.ErrClosed
					}
					_ = conn.Close()
				default:
					return nil, net.ErrClosed
				}
			}
		}
	}
}

// Close signals the listener to stop accepting connections and drains
// any buffered connections that have not yet been accepted.
func (l *chanListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		for {
			select {
			case conn, ok := <-l.ch:
				if !ok {
					return
				}
				_ = conn.Close()
			default:
				return
			}
		}
	})
	return nil
}

// Addr returns the listener's network address.
func (l *chanListener) Addr() net.Addr {
	return l.addr
}

var _ net.Listener = (*chanListener)(nil)
