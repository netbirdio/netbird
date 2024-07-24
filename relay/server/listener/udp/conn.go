package udp

import (
	"io"
	"net"
	"time"
)

type Conn struct {
	*net.UDPConn
	addr       *net.UDPAddr
	msgChannel chan []byte
}

func NewConn(conn *net.UDPConn, addr *net.UDPAddr) *Conn {
	return &Conn{
		UDPConn:    conn,
		addr:       addr,
		msgChannel: make(chan []byte),
	}
}

func (u *Conn) Read(b []byte) (n int, err error) {
	msg, ok := <-u.msgChannel
	if !ok {
		return 0, io.EOF
	}

	n = copy(b, msg)
	return n, nil
}

func (u *Conn) Write(b []byte) (n int, err error) {
	return u.UDPConn.WriteTo(b, u.addr)
}

func (u *Conn) Close() error {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (u *Conn) LocalAddr() net.Addr {
	return u.UDPConn.LocalAddr()
}

func (u *Conn) RemoteAddr() net.Addr {
	return u.addr
}

func (u *Conn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("implement SetDeadline")
}

func (u *Conn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("implement SetReadDeadline")
}

func (u *Conn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("implement SetWriteDeadline")
}

func (u *Conn) onNewMsg(b []byte) {
	u.msgChannel <- b
}
