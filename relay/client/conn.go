package client

import (
	"net"
	"time"
)

type Conn struct {
	client    *Client
	channelID uint16
	readerFn  func(b []byte) (n int, err error)
}

func NewConn(client *Client, channelID uint16, readerFn func(b []byte) (n int, err error)) *Conn {
	c := &Conn{
		client:    client,
		channelID: channelID,
		readerFn:  readerFn,
	}

	return c
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.client.writeTo(c.channelID, p)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.readerFn(b)
}

func (c *Conn) Close() error {
	return nil
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
