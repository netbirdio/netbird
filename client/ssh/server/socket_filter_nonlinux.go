//go:build !linux

package server

import (
	"net"
)

// attachSocketFilter is not supported on non-Linux platforms
func attachSocketFilter(listener net.Listener, wgIfIndex int) error {
	// Socket filtering is not available on non-Linux platforms - no-op
	return nil
}

// detachSocketFilter is not supported on non-Linux platforms
func detachSocketFilter(listener net.Listener) error {
	// Socket filtering is not available on non-Linux platforms - no-op
	return nil
}
