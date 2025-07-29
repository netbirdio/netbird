package net

import (
	"net"
)

// ListenerConfig extends the standard net.ListenConfig with the ability to execute hooks before
// responding via the socket and after closing. This can be used to bypass the VPN for listeners.
type ListenerConfig struct {
	*net.ListenConfig
}

// NewListener creates a new ListenerConfig instance.
func NewListener() *ListenerConfig {
	listener := &ListenerConfig{
		ListenConfig: &net.ListenConfig{},
	}
	listener.init()

	return listener
}
