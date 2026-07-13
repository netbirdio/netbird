//go:build !linux

package capture

import "errors"

// AFPacketCapture is not available on this platform.
type AFPacketCapture struct{}

// NewAFPacketCapture returns nil on non-Linux platforms.
func NewAFPacketCapture(string, *Session) *AFPacketCapture { return nil }

// Start returns an error on non-Linux platforms.
func (c *AFPacketCapture) Start() error {
	return errors.New("AF_PACKET capture is only supported on Linux")
}

// Stop is a no-op on non-Linux platforms.
func (c *AFPacketCapture) Stop() {
	// no-op on non-Linux platforms
}

// Offer is a no-op on non-Linux platforms.
func (c *AFPacketCapture) Offer([]byte, bool) {
	// no-op on non-Linux platforms
}
