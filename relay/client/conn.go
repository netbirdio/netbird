package client

import (
	"io"
	"net"
	"time"
)

type Conn struct {
	client      *Client
	dstID       []byte
	dstStringID string
	messageChan chan Msg
	instanceURL *RelayAddr
}

func NewConn(client *Client, dstID []byte, dstStringID string, messageChan chan Msg, instanceURL *RelayAddr) *Conn {
	c := &Conn{
		client:      client,
		dstID:       dstID,
		dstStringID: dstStringID,
		messageChan: messageChan,
		instanceURL: instanceURL,
	}

	return c
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.client.writeTo(c.dstStringID, c.dstID, p)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	msg, ok := <-c.messageChan
	if !ok {
		return 0, io.EOF
	}

	n = copy(b, msg.Payload)
	msg.Free()
	return n, nil
}

func (c *Conn) Close() error {
	return c.client.closeConn(c.dstStringID)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.client.relayConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.instanceURL
}

func (c *Conn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("SetDeadline is not implemented")
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("SetReadDeadline is not implemented")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("SetReadDeadline is not implemented")
}
