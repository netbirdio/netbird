//go:build !linux

package inspect

import "net"

// newOutboundDialer returns a plain dialer on non-Linux platforms.
// TPROXY is Linux-only, so no fwmark clearing is needed.
func newOutboundDialer() net.Dialer {
	return net.Dialer{}
}
