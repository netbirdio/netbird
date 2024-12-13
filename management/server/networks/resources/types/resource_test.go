package types

import (
	"testing"
)

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		input        string
		expectedType NetworkResourceType
		expectedErr  bool
	}{
		// Valid host IPs
		{"1.1.1.1", host, false},
		{"1.1.1.1/32", host, false},
		// Valid subnets
		{"192.168.1.0/24", subnet, false},
		{"10.0.0.0/16", subnet, false},
		// Valid domains
		{"example.com", domain, false},
		{"*.example.com", domain, false},
		{"sub.example.com", domain, false},
		// Invalid inputs
		{"invalid", "", true},
		{"1.1.1.1/abc", "", true},
		{"1234", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := GetResourceType(tt.input)
			if result != tt.expectedType {
				t.Errorf("Expected type %v, got %v", tt.expectedType, result)
			}

			if tt.expectedErr && err == nil {
				t.Errorf("Expected error, got nil")
			}
		})
	}
}
