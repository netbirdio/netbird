package netutil

import (
	"net"
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/shared/management/domain"
)

// NormalizeHost canonicalizes an HTTP Host/SNI name for use as a routing or
// authorization key. It removes an optional port and DNS root dot, lowercases
// the name, and converts Unicode labels to their IDNA ASCII representation.
func NormalizeHost(authority string) string {
	host := strings.TrimSpace(authority)
	if split, _, err := net.SplitHostPort(host); err == nil {
		host = split
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimRight(host, ".")
	host = strings.ToLower(host)
	if canonical, err := domain.FromString(host); err == nil {
		return canonical.PunycodeString()
	}
	return host
}

// NormalizeAuthority canonicalizes the hostname portion of an HTTP authority
// while retaining IPv6 brackets and any explicit port for redirect URIs.
func NormalizeAuthority(authority string) string {
	authority = strings.TrimSpace(authority)
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		host = NormalizeHost(authority)
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(NormalizeHost(host), port)
}
