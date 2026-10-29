package types

import (
	"net/netip"
	"testing"
)

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		input          string
		expectedType   NetworkResourceType
		expectedErr    bool
		expectedDomain string
		expectedPrefix netip.Prefix
	}{
		// Valid host IPs
		{"1.1.1.1", Host, false, "", netip.MustParsePrefix("1.1.1.1/32")},
		{"1.1.1.1/32", Host, false, "", netip.MustParsePrefix("1.1.1.1/32")},
		// Valid subnets
		{"192.168.1.0/24", Subnet, false, "", netip.MustParsePrefix("192.168.1.0/24")},
		{"10.0.0.0/16", Subnet, false, "", netip.MustParsePrefix("10.0.0.0/16")},
		// Valid domains
		{"example.com", Domain, false, "example.com", netip.Prefix{}},
		{"*.example.com", Domain, false, "*.example.com", netip.Prefix{}},
		{"sub.example.com", Domain, false, "sub.example.com", netip.Prefix{}},
		{"example.x", Domain, false, "example.x", netip.Prefix{}},
		{"internal", Domain, false, "internal", netip.Prefix{}},
		// Invalid inputs
		{"1.1.1.1/abc", "", true, "", netip.Prefix{}},
		{"-invalid.com", "", true, "", netip.Prefix{}},
		{"", "", true, "", netip.Prefix{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, domain, prefix, err := GetResourceType(tt.input)

			if result != tt.expectedType {
				t.Errorf("Expected type %v, got %v", tt.expectedType, result)
			}

			if tt.expectedErr && err == nil {
				t.Errorf("Expected error, got nil")
			}

			if prefix != tt.expectedPrefix {
				t.Errorf("Expected address %v, got %v", tt.expectedPrefix, prefix)
			}

			if domain != tt.expectedDomain {
				t.Errorf("Expected domain %v, got %v", tt.expectedDomain, domain)
			}
		})
	}
}
