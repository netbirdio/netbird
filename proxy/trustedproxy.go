package proxy

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses a comma-separated list of CIDR prefixes or bare IPs
// into a slice of netip.Prefix values suitable for trusted proxy configuration.
// Bare IPs are converted to single-host prefixes (/32 or /128).
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	if raw == "" {
		return nil, nil
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
	return prefixes, nil
}
