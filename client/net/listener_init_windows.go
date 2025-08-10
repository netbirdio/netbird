package net

import (
	"syscall"
)

func (l *ListenerConfig) init() {
	// TODO: this will select a single source interface, but for UDP we can have various source interfaces and IP addresses.
	// For now we stick to the one that matches the request IP address, which can be the unspecified IP. In this case
	// the interface will be selected that serves the default route.
	l.ListenConfig.Control = func(network, address string, c syscall.RawConn) error {
		return applyUnicastIFToSocket(network, address, c)
	}
}
