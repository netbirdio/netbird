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
