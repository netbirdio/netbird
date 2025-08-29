//go:build !ios

package net

import (
	"net"

	log "github.com/sirupsen/logrus"
)

// Conn wraps a net.Conn to override the Close method
type Conn struct {
	net.Conn
	ID ConnectionID
}

// Close overrides the net.Conn Close method to execute all registered hooks after closing the connection
func (c *Conn) Close() error {
	err := c.Conn.Close()

	dialerCloseHooksMutex.RLock()
	defer dialerCloseHooksMutex.RUnlock()

	for _, hook := range dialerCloseHooks {
		if err := hook(c.ID, &c.Conn); err != nil {
			log.Errorf("Error executing dialer close hook: %v", err)
		}
	}

	return err
}
