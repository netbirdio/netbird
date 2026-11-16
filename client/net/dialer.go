package net

import (
	"net"
)

// Dialer extends the standard net.Dialer with the ability to execute hooks before
// and after connections. This can be used to bypass the VPN for connections using this dialer.
type Dialer struct {
	*net.Dialer
}

// NewDialer returns a customized net.Dialer with overridden Control method.
// Connections start with the Go default TCP keepalive. A connection that ends
// up carrying an aligned heartbeat stream is switched once the server confirms
// it (shared/alignedhb/keepalive).
func NewDialer() *Dialer {
	dialer := &Dialer{
		Dialer: &net.Dialer{},
	}
	dialer.init()
	return dialer
}
