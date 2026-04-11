package inspect

import (
	"net"
	"syscall"
)

// newOutboundDialer creates a net.Dialer that clears the socket fwmark.
// In kernel TPROXY mode, accepted connections inherit the TPROXY fwmark.
// Without clearing it, outbound connections from the proxy would match
// the ip rule (fwmark -> local loopback) and loop back to the proxy
// instead of reaching the real destination.
func newOutboundDialer() net.Dialer {
	return net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 0)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
}
