package trustedproxy

import (
	"fmt"
	"net/netip"
	"strings"
)

// List holds a parsed set of trusted upstream proxy prefixes and answers trust
// questions against it. The zero value (and a nil *List) is a valid, empty list
// that never trusts any address, so callers can use it without a nil check.
type List struct {
	prefixes []netip.Prefix
}

// Parse parses a comma-separated list of CIDR prefixes or bare IPs into a List.
// Bare IPs are converted to single-host prefixes (/32 or /128). An empty input
// yields an empty List that trusts nothing.
func Parse(raw string) (*List, error) {
	if raw == "" {
		return &List{}, nil
	}

	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(part)
		if err == nil {
			prefixes = append(prefixes, prefix)
			continue
		}

		addr, addrErr := netip.ParseAddr(part)
		if addrErr != nil {
			return nil, fmt.Errorf("parse trusted proxy %q: not a valid CIDR or IP: %w", part, addrErr)
		}

		bits := 32
		if addr.Is6() {
			bits = 128
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
	}
	return &List{prefixes: prefixes}, nil
}

// FromPrefixes wraps an already-parsed set of prefixes in a List.
func FromPrefixes(prefixes []netip.Prefix) *List {
	return &List{prefixes: prefixes}
}

// Empty reports whether the list contains no prefixes.
func (l *List) Empty() bool {
	return l == nil || len(l.prefixes) == 0
}

// IsTrusted reports whether the given host:port or bare IP falls within the list.
func (l *List) IsTrusted(remoteAddr string) bool {
	if l.Empty() {
		return false
	}
	return l.Contains(ExtractHostIP(remoteAddr))
}

// Contains reports whether the given address falls within any trusted prefix.
func (l *List) Contains(addr netip.Addr) bool {
	if l.Empty() || !addr.IsValid() {
		return false
	}
	for _, prefix := range l.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ResolveClientIP extracts the real client IP from X-Forwarded-For using the
// list. It walks the XFF chain right-to-left, skipping IPs that match trusted
// prefixes; the first untrusted IP is the real client. If the list is empty or
// remoteAddr is not trusted, it returns the remoteAddr IP directly, ignoring any
// forwarding headers.
func (l *List) ResolveClientIP(remoteAddr, xff string) netip.Addr {
	remoteIP := ExtractHostIP(remoteAddr)

	if l.Empty() || !l.Contains(remoteIP) {
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
		if !l.Contains(addr) {
			return addr
		}
	}

	if first := strings.TrimSpace(parts[0]); first != "" {
		if addr, err := netip.ParseAddr(first); err == nil {
			return addr.Unmap()
		}
	}
	return remoteIP
}

// ExtractHostIP parses the IP from a host:port string and returns it unmapped.
func ExtractHostIP(hostPort string) netip.Addr {
	if ap, err := netip.ParseAddrPort(hostPort); err == nil {
		return ap.Addr().Unmap()
	}
	if addr, err := netip.ParseAddr(hostPort); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}
