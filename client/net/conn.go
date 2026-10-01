//go:build !ios

package net

import (
	"io"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/net/hooks"
)

// Conn wraps a net.Conn to override the Close method
type Conn struct {
	net.Conn
	ID hooks.ConnectionID
}

// Close overrides the net.Conn Close method to execute all registered hooks after closing the connection.
func (c *Conn) Close() error {
	return closeConn(c.ID, c.Conn)
}

// TCPConn wraps net.TCPConn to override its Close method to include hook functionality.
type TCPConn struct {
	*net.TCPConn
	ID hooks.ConnectionID
}

// Close overrides the net.TCPConn Close method to execute all registered hooks after closing the connection.
func (c *TCPConn) Close() error {
	return closeConn(c.ID, c.TCPConn)
}

// closeConn is a helper function to close connections and execute close hooks.
func closeConn(id hooks.ConnectionID, conn io.Closer) error {
	err := conn.Close()
	cleanupConnID(id)
	return err
}

// cleanupConnID executes close hooks for a connection ID.
func cleanupConnID(id hooks.ConnectionID) {
	closeHooks := hooks.GetCloseHooks()
	for _, hook := range closeHooks {
		if err := hook(id); err != nil {
			log.Errorf("Error executing close hook: %v", err)
		}
	}
}
