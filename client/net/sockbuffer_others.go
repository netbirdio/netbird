//go:build !linux

package net

// forceSocketBuffers is a no-op on non-Linux platforms: the SO_*BUFFORCE options
// are Linux-specific, so callers fall back to the portable SetReadBuffer/
// SetWriteBuffer path.
func forceSocketBuffers(_ any, _ int) bool {
	return false
}

// logRelaySocketBuffers is a no-op on non-Linux platforms.
func logRelaySocketBuffers(_ any) {}
