package peer

import (
	"net"
	"time"
)

type MyNetConn struct {
	remoteConn net.PacketConn
	remoteAddr net.Addr
}

func NewMyNetConn(remoteConn net.PacketConn, remoteAddr net.Addr) net.Conn {
	return &MyNetConn{
		remoteConn: remoteConn,
		remoteAddr: remoteAddr,
	}
}

func (m *MyNetConn) Read(b []byte) (n int, err error) {
	n, _, err = m.remoteConn.ReadFrom(b)
	return
}

func (m *MyNetConn) Write(b []byte) (n int, err error) {
	n, err = m.remoteConn.WriteTo(b, m.remoteAddr)
	return
}

func (m *MyNetConn) Close() error {
	return m.remoteConn.Close()
}

func (m *MyNetConn) LocalAddr() net.Addr {
	return m.remoteConn.LocalAddr()
}

func (m *MyNetConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *MyNetConn) SetDeadline(t time.Time) error {
	return m.remoteConn.SetDeadline(t)
}

func (m *MyNetConn) SetReadDeadline(t time.Time) error {
	return m.remoteConn.SetReadDeadline(t)
}

func (m *MyNetConn) SetWriteDeadline(t time.Time) error {
	return m.remoteConn.SetWriteDeadline(t)
}
