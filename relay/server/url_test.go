package server

import "testing"

func TestGetInstanceURL(t *testing.T) {
	tests := []struct {
		name           string
		exposedAddress string
		tlsSupported   bool
		expectedURL    string
		expectError    bool
	}{
		{"Valid address with TLS", "example.com", true, "rels://example.com", false},
		{"Valid address without TLS", "example.com", false, "rel://example.com", false},
		{"Valid address with scheme", "rel://example.com", false, "rel://example.com", false},
		{"Invalid address with non TLS scheme and TLS true", "rel://example.com", true, "", true},
		{"Valid address with TLS scheme", "rels://example.com", true, "rels://example.com", false},
		{"Valid address with TLS scheme and TLS false", "rels://example.com", false, "rels://example.com", false},
		{"Valid address with TLS scheme and custom port", "rels://example.com:9300", true, "rels://example.com:9300", false},
		{"Invalid address with multiple schemes", "rel://rels://example.com", false, "", true},
		{"Invalid address with unsupported scheme", "http://example.com", false, "", true},
		{"Invalid address format", "://example.com", false, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := getInstanceURL(tt.exposedAddress, tt.tlsSupported)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
			if !tt.expectError && url != nil && url.String() != tt.expectedURL {
				t.Errorf("expected URL: %s, got: %s", tt.expectedURL, url.String())
			}
			if tt.expectError && url != nil {
				t.Errorf("expected nil URL on error, got: %s", url.String())
			}
		})
	}
}
