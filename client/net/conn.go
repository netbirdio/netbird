//go:build !ios

package net

import (
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/net/hooks"
)

// Conn wraps a net.Conn to override the Close method
type Conn struct {
	net.Conn
	ID hooks.ConnectionID
}

// Close overrides the net.Conn Close method to execute all registered hooks after closing the connection
func (c *Conn) Close() error {
	err := c.Conn.Close()

	dialerCloseHooks := hooks.GetDialerCloseHooks()
	for _, hook := range dialerCloseHooks {
		if err := hook(c.ID, &c.Conn); err != nil {
			log.Errorf("Error executing dialer close hook: %v", err)
		}
	}

	return err
}
