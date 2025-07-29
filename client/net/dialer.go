package net

import (
	"net"
)

// Dialer extends the standard net.Dialer with the ability to execute hooks before
// and after connections. This can be used to bypass the VPN for connections using this dialer.
type Dialer struct {
	*net.Dialer
}

// NewDialer returns a customized net.Dialer with overridden Control method
func NewDialer() *Dialer {
	dialer := &Dialer{
		Dialer: &net.Dialer{},
	}
	dialer.init()

	return dialer
}
