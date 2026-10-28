package service

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func normalizeExposeTargetHost(raw string) (string, error) {
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

	host = stripExposeDNSRootDot(host)
	if host == "" {
		return "", fmt.Errorf("target host cannot be empty")
	}

	inner, bracketed, err := unwrapExposeTargetHostBrackets(host)
	if err != nil {
		return "", err
	}
	if inner == "" {
		return "", fmt.Errorf("target host cannot be empty")
	}

	addr, err := netip.ParseAddr(inner)
	if err != nil {
		if bracketed {
			return "", fmt.Errorf("target host %q is not a valid hostname", host)
		}
		return normalizeExposeTargetHostname(inner)
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

func stripExposeDNSRootDot(host string) string {
	if strings.HasSuffix(host, ".") && !strings.HasSuffix(host, "]") {
		return strings.TrimSuffix(host, ".")
	}
	return host
}

func unwrapExposeTargetHostBrackets(host string) (string, bool, error) {
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") || len(host) < 3 {
			return "", false, fmt.Errorf("target host %q has unbalanced brackets", host)
		}
		inner := host[1 : len(host)-1]
		if inner == "" || strings.ContainsAny(inner, "[]") {
			return "", false, fmt.Errorf("target host %q has unbalanced brackets", host)
		}
		return inner, true, nil
	}
	if strings.ContainsAny(host, "[]") {
		return "", false, fmt.Errorf("target host %q has unbalanced brackets", host)
	}
	return host, false, nil
}

func normalizeExposeTargetHostname(name string) (string, error) {
	normalized := strings.ToLower(name)
	if isExposeLoopbackHostname(normalized) {
		return "", fmt.Errorf("target host must not be a loopback address")
	}
	if !validExposeDNSHostname(normalized) {
		return "", fmt.Errorf("target host %q is not a valid hostname", name)
	}
	return normalized, nil
}

func isExposeLoopbackHostname(name string) bool {
	return name == "localhost" || strings.HasSuffix(name, ".localhost")
}

func validExposeDNSHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	allNumeric := true
	for _, label := range labels {
		if !validExposeDNSLabel(label) {
			return false
		}
		if !isExposeNumericLabel(label) {
			allNumeric = false
		}
	}
	return !allNumeric
}

func validExposeDNSLabel(label string) bool {
	n := len(label)
	if n == 0 || n > 63 {
		return false
	}
	if label[0] == '-' || label[n-1] == '-' {
		return false
	}
	for i := 0; i < n; i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func isExposeNumericLabel(label string) bool {
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}
