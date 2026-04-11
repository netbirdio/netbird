//go:build !linux

package inspect

import (
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
)

// newTPROXYListener is not supported on non-Linux platforms.
func newTPROXYListener(_ *log.Entry, addr netip.AddrPort, _ netip.Prefix) (net.Listener, error) {
	return nil, fmt.Errorf("TPROXY listener not supported on this platform (requested %s)", addr)
}

// getOriginalDst is not supported on non-Linux platforms.
func getOriginalDst(_ net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST not supported on this platform")
}
