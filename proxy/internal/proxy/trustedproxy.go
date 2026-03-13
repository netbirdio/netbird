package proxy

import (
	"net/netip"
	"strings"
)

// IsTrustedProxy checks if the given IP string falls within any of the trusted prefixes.
func IsTrustedProxy(ipStr string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || len(trusted) == 0 {
		return false
	}
	return isTrustedAddr(addr.Unmap(), trusted)
}

// ResolveClientIP extracts the real client IP from X-Forwarded-For using the trusted proxy list.
// It walks the XFF chain right-to-left, skipping IPs that match trusted prefixes.
// The first untrusted IP is the real client.
//
// If the trusted list is empty or remoteAddr is not trusted, it returns the
// remoteAddr IP directly (ignoring any forwarding headers).
func ResolveClientIP(remoteAddr, xff string, trusted []netip.Prefix) netip.Addr {
	remoteIP := extractHostIP(remoteAddr)

	if len(trusted) == 0 || !isTrustedAddr(remoteIP, trusted) {
		return remoteIP
	}

	if xff == "" {
		return remoteIP
	}

	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !isTrustedAddr(addr, trusted) {
			return addr
		}
	}

	// All IPs in XFF are trusted; return the leftmost as best guess.
	if first := strings.TrimSpace(parts[0]); first != "" {
		if addr, err := netip.ParseAddr(first); err == nil {
			return addr.Unmap()
		}
	}
	return remoteIP
}

// extractHostIP parses the IP from a host:port string and returns it unmapped.
func extractHostIP(hostPort string) netip.Addr {
	if ap, err := netip.ParseAddrPort(hostPort); err == nil {
		return ap.Addr().Unmap()
	}
	if addr, err := netip.ParseAddr(hostPort); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}

// isTrustedAddr checks if the given address falls within any of the trusted prefixes.
func isTrustedAddr(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
