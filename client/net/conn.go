//go:build !ios

package net

import (
	"net"

	"github.com/netbirdio/netbird/client/net/hooks"
)

// Conn wraps a net.Conn to override the Close method
type Conn struct {
	net.Conn
	ID hooks.ConnectionID
}

// Close overrides the net.Conn Close method to execute all registered hooks after closing the connection
// Close overrides the net.Conn Close method to execute all registered hooks before closing the connection.
func (c *Conn) Close() error {
	return closeConn(c.ID, c.Conn)
}

// TCPConn wraps net.TCPConn to override its Close method to include hook functionality.
type TCPConn struct {
	*net.TCPConn
	ID hooks.ConnectionID
}

// Close overrides the net.TCPConn Close method to execute all registered hooks before closing the connection.
func (c *TCPConn) Close() error {
	return closeConn(c.ID, c.TCPConn)
}
