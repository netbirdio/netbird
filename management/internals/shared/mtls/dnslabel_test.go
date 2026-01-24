package mtls

import (
	"testing"
)

func TestGenerateUniqueDNSLabel(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		domain   string
		wantLen  int // Check length is within bounds
	}{
		{
			name:     "simple hostname and domain",
			hostname: "win10-pc",
			domain:   "corp.local",
			wantLen:  17, // "win10-pc" + "-" + 8 hex chars
		},
		{
			name:     "uppercase hostname normalized",
			hostname: "WIN10-PC",
			domain:   "CORP.LOCAL",
			wantLen:  17,
		},
		{
			name:     "very long hostname truncated",
			hostname: "this-is-a-very-very-very-very-very-very-very-long-hostname-that-exceeds-limit",
			domain:   "corp.local",
			wantLen:  63, // Should be truncated to max 63 chars
		},
		{
			name:     "hostname with underscores",
			hostname: "win_10_pc",
			domain:   "corp.local",
			wantLen:  18, // "win-10-pc" + "-" + 8 hex chars
		},
		{
			name:     "hostname with spaces",
			hostname: "win 10 pc",
			domain:   "corp.local",
			wantLen:  18,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateUniqueDNSLabel(tt.hostname, tt.domain)

			// Check length constraint
			if len(got) > MaxDNSLabelLength {
				t.Errorf("GenerateUniqueDNSLabel() returned label longer than %d chars: %s (len=%d)",
					MaxDNSLabelLength, got, len(got))
			}

			// Check RFC 1123 compliance
			if err := ValidateDNSLabel(got); err != nil {
				t.Errorf("GenerateUniqueDNSLabel() returned invalid label: %s, error: %v", got, err)
			}
		})
	}
}

func TestGenerateUniqueDNSLabel_Uniqueness(t *testing.T) {
	// Same hostname, different domains should produce different labels
	label1 := GenerateUniqueDNSLabel("win10-pc", "customer-a.local")
	label2 := GenerateUniqueDNSLabel("win10-pc", "customer-b.local")

	if label1 == label2 {
		t.Errorf("Expected different labels for different domains, got same: %s", label1)
	}

	// Same domain, different hostnames should produce different labels
	label3 := GenerateUniqueDNSLabel("win10-pc", "corp.local")
	label4 := GenerateUniqueDNSLabel("win11-pc", "corp.local")

	if label3 == label4 {
		t.Errorf("Expected different labels for different hostnames, got same: %s", label3)
	}

	// Same hostname+domain should produce same label (deterministic)
	label5 := GenerateUniqueDNSLabel("server1", "example.com")
	label6 := GenerateUniqueDNSLabel("server1", "example.com")

	if label5 != label6 {
		t.Errorf("Expected same label for same input, got different: %s vs %s", label5, label6)
	}

	// Case-insensitive: same FQDN with different case should produce same label
	label7 := GenerateUniqueDNSLabel("SERVER1", "EXAMPLE.COM")
	if label5 != label7 {
		t.Errorf("Expected case-insensitive matching, got different: %s vs %s", label5, label7)
	}
}

func TestValidateDNSLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		wantErr bool
	}{
		{
			name:    "valid simple label",
			label:   "hostname",
			wantErr: false,
		},
		{
			name:    "valid with numbers",
			label:   "host123",
			wantErr: false,
		},
		{
			name:    "valid with hyphens",
			label:   "my-hostname-01",
			wantErr: false,
		},
		{
			name:    "valid machine label with hash",
			label:   "win10-pc-a1b2c3d4",
			wantErr: false,
		},
		{
			name:    "empty label",
			label:   "",
			wantErr: true,
		},
		{
			name:    "starts with hyphen",
			label:   "-hostname",
			wantErr: true,
		},
		{
			name:    "ends with hyphen",
			label:   "hostname-",
			wantErr: true,
		},
		{
			name:    "contains uppercase",
			label:   "Hostname",
			wantErr: true,
		},
		{
			name:    "contains underscore",
			label:   "host_name",
			wantErr: true,
		},
		{
			name:    "contains space",
			label:   "host name",
			wantErr: true,
		},
		{
			name:    "too long (64 chars)",
			label:   "a123456789012345678901234567890123456789012345678901234567890123",
			wantErr: true,
		},
		{
			name:    "max length (63 chars)",
			label:   "a12345678901234567890123456789012345678901234567890123456789012",
			wantErr: false,
		},
		{
			name:    "single char",
			label:   "a",
			wantErr: false,
		},
		{
			name:    "starts with number",
			label:   "1hostname",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSLabel(tt.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDNSLabel(%q) error = %v, wantErr %v", tt.label, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeForDNS(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{
			name:     "already valid",
			hostname: "hostname",
			want:     "hostname",
		},
		{
			name:     "uppercase to lowercase",
			hostname: "HOSTNAME",
			want:     "hostname",
		},
		{
			name:     "underscores to hyphens",
			hostname: "host_name",
			want:     "host-name",
		},
		{
			name:     "spaces to hyphens",
			hostname: "host name",
			want:     "host-name",
		},
		{
			name:     "dots to hyphens",
			hostname: "host.name",
			want:     "host-name",
		},
		{
			name:     "leading hyphens removed",
			hostname: "_hostname",
			want:     "hostname",
		},
		{
			name:     "trailing hyphens removed",
			hostname: "hostname_",
			want:     "hostname",
		},
		{
			name:     "multiple consecutive hyphens collapsed",
			hostname: "host__name",
			want:     "host-name",
		},
		{
			name:     "special chars dropped",
			hostname: "host@name!",
			want:     "hostname",
		},
		{
			name:     "empty after sanitization",
			hostname: "@#$%",
			want:     "peer", // default fallback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForDNS(tt.hostname)
			if got != tt.want {
				t.Errorf("sanitizeForDNS(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestCheckDNSLabelCollision(t *testing.T) {
	// No collision
	if CheckDNSLabelCollision("test-label", "") {
		t.Error("Expected no collision when existingPeerID is empty")
	}

	// Collision detected
	if !CheckDNSLabelCollision("test-label", "existing-peer-id") {
		t.Error("Expected collision when existingPeerID is not empty")
	}
}
