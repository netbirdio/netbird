package types

import (
	"testing"
)

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		input        string
		expectedType NetworkResourceType
		expectedErr  bool
		expectedAddr string
	}{
		// Valid host IPs
		{"1.1.1.1", host, false, "1.1.1.1/32"},
		{"1.1.1.1/32", host, false, "1.1.1.1/32"},
		// Valid subnets
		{"192.168.1.0/24", subnet, false, "192.168.1.0/24"},
		{"10.0.0.0/16", subnet, false, "10.0.0.0/16"},
		// Valid domains
		{"example.com", domain, false, "example.com"},
		{"*.example.com", domain, false, "*.example.com"},
		{"sub.example.com", domain, false, "sub.example.com"},
		// Invalid inputs
		{"invalid", "", true, ""},
		{"1.1.1.1/abc", "", true, ""},
		{"1234", "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, addr, err := GetResourceType(tt.input)
			if result != tt.expectedType {
				t.Errorf("Expected type %v, got %v", tt.expectedType, result)
			}

			if tt.expectedErr && err == nil {
				t.Errorf("Expected error, got nil")
			}

			if addr != tt.expectedAddr {
				t.Errorf("Expected address %v, got %v", tt.expectedAddr, addr)
			}
		})
	}
}
