package udp

import (
	"io"
	"net"
	"time"
)

type UDPConn struct {
	*net.UDPConn
	addr       *net.UDPAddr
	msgChannel chan []byte
}

func NewConn(conn *net.UDPConn, addr *net.UDPAddr) *UDPConn {
	return &UDPConn{
		UDPConn:    conn,
		addr:       addr,
		msgChannel: make(chan []byte),
	}
}

func (u *UDPConn) Read(b []byte) (n int, err error) {
	msg, ok := <-u.msgChannel
	if !ok {
		return 0, io.EOF
	}

	n = copy(b, msg)
	return n, nil
}

func (u *UDPConn) Write(b []byte) (n int, err error) {
	return u.UDPConn.WriteTo(b, u.addr)
}

func (u *UDPConn) Close() error {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (u *UDPConn) LocalAddr() net.Addr {
	return u.UDPConn.LocalAddr()
}

func (u *UDPConn) RemoteAddr() net.Addr {
	return u.addr
}

func (u *UDPConn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (u *UDPConn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (u *UDPConn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (u *UDPConn) onNewMsg(b []byte) {
	u.msgChannel <- b
}
