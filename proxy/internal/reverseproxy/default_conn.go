package reverseproxy

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// defaultConn is a lazy connection wrapper that uses the standard network dialer
// This is useful for testing or development when not using WireGuard tunnels
type defaultConn struct {
	dialer *net.Dialer
	mu     sync.Mutex
	conns  map[string]net.Conn // cache connections by "network:address"
}

func (dc *defaultConn) Read(b []byte) (n int, err error) {
	return 0, fmt.Errorf("Read not supported on defaultConn - use dial via Transport")
}

func (dc *defaultConn) Write(b []byte) (n int, err error) {
	return 0, fmt.Errorf("Write not supported on defaultConn - use dial via Transport")
}

func (dc *defaultConn) Close() error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	for _, conn := range dc.conns {
		conn.Close()
	}
	dc.conns = make(map[string]net.Conn)
	return nil
}

func (dc *defaultConn) LocalAddr() net.Addr                { return nil }
func (dc *defaultConn) RemoteAddr() net.Addr               { return nil }
func (dc *defaultConn) SetDeadline(t time.Time) error      { return nil }
func (dc *defaultConn) SetReadDeadline(t time.Time) error  { return nil }
func (dc *defaultConn) SetWriteDeadline(t time.Time) error { return nil }

// NewDefaultConn creates a connection wrapper that uses the standard network dialer
// This is useful for testing or development when not using WireGuard tunnels
// The actual dialing happens when the HTTP Transport calls DialContext
func NewDefaultConn() net.Conn {
	return &defaultConn{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		conns: make(map[string]net.Conn),
	}
}
