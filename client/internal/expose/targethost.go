package expose

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// NormalizeTargetHost trims and validates a --with-target-host value.
// The host must be an IP or DNS name with no scheme, port, or path.
func NormalizeTargetHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", fmt.Errorf("target host cannot be empty")
	}
	if strings.Contains(host, "://") {
		return "", fmt.Errorf("target host must not include a scheme")
	}
	if strings.ContainsAny(host, "/\\?#") {
		return "", fmt.Errorf("target host must not include a path")
	}
	if strings.ContainsAny(host, " \t@") {
		return "", fmt.Errorf("target host %q contains invalid characters", host)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "", fmt.Errorf("target host %q must not include a port", host)
	}

	noBrackets := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if noBrackets == "" {
		return "", fmt.Errorf("target host cannot be empty")
	}

	addr, err := netip.ParseAddr(noBrackets)
	if err != nil {
		if strings.EqualFold(noBrackets, "localhost") {
			return "", fmt.Errorf("target host must not be a loopback address")
		}
		return noBrackets, nil
	}

	addr = addr.Unmap()
	if addr.IsLoopback() {
		return "", fmt.Errorf("target host must not be a loopback address")
	}
	if addr.Zone() != "" || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return "", fmt.Errorf("invalid target host %s", addr)
	}
	return addr.String(), nil
}
