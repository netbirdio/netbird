package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsProxyAddressValid(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		valid bool
	}{
		{name: "valid domain", addr: "eu.proxy.netbird.io", valid: true},
		{name: "valid subdomain", addr: "byop.proxy.example.com", valid: true},
		{name: "valid IPv4", addr: "10.0.0.1", valid: true},
		{name: "valid IPv4 public", addr: "203.0.113.10", valid: true},
		{name: "valid IPv6", addr: "::1", valid: true},
		{name: "valid IPv6 full", addr: "2001:db8::1", valid: true},
		{name: "empty string", addr: "", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, isProxyAddressValid(tt.addr))
		})
	}
}

// TestCanonicalProxyAddress pins the canonical form the store keeps. Every
// capability, ownership and routing lookup matches cluster_address exactly, so
// one host must have exactly one spelling in that column — which is what lets
// those queries stay exact (and keep using the index) instead of folding case
// per query.
func TestCanonicalProxyAddress(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		canonical string
		ok        bool
	}{
		{name: "lowercase domain unchanged", addr: "eu.proxy.netbird.io", canonical: "eu.proxy.netbird.io", ok: true},
		{name: "mixed case domain folded", addr: "EU.Proxy.NetBird.io", canonical: "eu.proxy.netbird.io", ok: true},
		{name: "uppercase domain folded", addr: "BYOP.PROXY.EXAMPLE.COM", canonical: "byop.proxy.example.com", ok: true},
		{name: "unicode domain punycoded", addr: "pröxy.example.com", canonical: "xn--prxy-6qa.example.com", ok: true},
		// Same host, and idna alone would encode the two cases to different
		// labels, so this is the one that proves the fold happens first.
		{name: "mixed case unicode folds to the same label", addr: "PRÖXY.example.com", canonical: "xn--prxy-6qa.example.com", ok: true},
		{name: "ipv4 unchanged", addr: "203.0.113.10", canonical: "203.0.113.10", ok: true},
		{name: "mixed case ipv6 canonicalised", addr: "2001:DB8::1", canonical: "2001:db8::1", ok: true},
		{name: "empty string rejected", addr: "", ok: false},
		{name: "space rejected", addr: "eu proxy.example.com", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, ok := canonicalProxyAddress(tt.addr)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.canonical, canonical)
		})
	}
}
