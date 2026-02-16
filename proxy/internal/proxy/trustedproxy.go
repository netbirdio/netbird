package proxy

import (
	"net/netip"
	"strings"
)

// IsTrustedProxy checks if the given IP string falls within any of the trusted prefixes.
func IsTrustedProxy(ipStr string, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}

	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ResolveClientIP extracts the real client IP from X-Forwarded-For using the trusted proxy list.
// It walks the XFF chain right-to-left, skipping IPs that match trusted prefixes.
// The first untrusted IP is the real client.
//
// If the trusted list is empty or remoteAddr is not trusted, it returns the
// remoteAddr IP directly (ignoring any forwarding headers).
func ResolveClientIP(remoteAddr, xff string, trusted []netip.Prefix) string {
	remoteIP := extractClientIP(remoteAddr)

	if len(trusted) == 0 || !IsTrustedProxy(remoteIP, trusted) {
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
		if !IsTrustedProxy(ip, trusted) {
			return ip
		}
	}

	// All IPs in XFF are trusted; return the leftmost as best guess.
	if first := strings.TrimSpace(parts[0]); first != "" {
		return first
	}
	return remoteIP
}
