package client

import (
	"net"
	"time"
)

type Conn struct {
	client      *Client
	dstID       []byte
	dstStringID string
	readerFn    func(b []byte) (n int, err error)
}

func NewConn(client *Client, dstID []byte, dstStringID string, readerFn func(b []byte) (n int, err error)) *Conn {
	c := &Conn{
		client:      client,
		dstID:       dstID,
		dstStringID: dstStringID,
		readerFn:    readerFn,
	}

	return c
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.client.writeTo(c.dstStringID, c.dstID, p)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.readerFn(b)
}

func (c *Conn) Close() error {
	return c.client.closeConn(c.dstStringID)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.client.relayConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.client.relayConn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}
