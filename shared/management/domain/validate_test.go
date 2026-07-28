package domain

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDomains(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)

	tests := []struct {
		name     string
		domains  []string
		expected List
		wantErr  bool
	}{
		{
			name:     "Empty list",
			domains:  nil,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Valid ASCII domain",
			domains:  []string{"sub.ex-ample.com"},
			expected: List{"sub.ex-ample.com"},
			wantErr:  false,
		},
		{
			name:     "Valid uppercase domain normalized to lowercase",
			domains:  []string{"EXAMPLE.COM"},
			expected: List{"example.com"},
			wantErr:  false,
		},
		{
			name:     "Valid mixed case domain",
			domains:  []string{"ExAmPlE.CoM"},
			expected: List{"example.com"},
			wantErr:  false,
		},
		{
			name:     "Single letter TLD",
			domains:  []string{"example.x"},
			expected: List{"example.x"},
			wantErr:  false,
		},
		{
			name:     "Two letter domain labels",
			domains:  []string{"a.b"},
			expected: List{"a.b"},
			wantErr:  false,
		},
		{
			name:     "Single character domain",
			domains:  []string{"x"},
			expected: List{"x"},
			wantErr:  false,
		},
		{
			name:     "Wildcard with single letter TLD",
			domains:  []string{"*.x"},
			expected: List{"*.x"},
			wantErr:  false,
		},
		{
			name:     "Multi-level with single letter labels",
			domains:  []string{"a.b.c"},
			expected: List{"a.b.c"},
			wantErr:  false,
		},
		{
			name:     "Valid Unicode domain",
			domains:  []string{"münchen.de"},
			expected: List{"xn--mnchen-3ya.de"},
			wantErr:  false,
		},
		{
			name:     "Valid Unicode, all labels",
			domains:  []string{"中国.中国.中国"},
			expected: List{"xn--fiqs8s.xn--fiqs8s.xn--fiqs8s"},
			wantErr:  false,
		},
		{
			name:     "With underscores",
			domains:  []string{"_jabber._tcp.gmail.com"},
			expected: List{"_jabber._tcp.gmail.com"},
			wantErr:  false,
		},
		{
			name:     "Valid domain starting with digit",
			domains:  []string{"123.example.com"},
			expected: List{"123.example.com"},
			wantErr:  false,
		},
		// Numeric TLDs are allowed for internal/private DNS use cases.
		// While ICANN doesn't issue all-numeric gTLDs, the DNS protocol permits them
		// and resolvers like systemd-resolved handle them correctly.
		{
			name:     "Numeric TLD allowed",
			domains:  []string{"example.123"},
			expected: List{"example.123"},
			wantErr:  false,
		},
		{
			name:     "Single digit TLD allowed",
			domains:  []string{"example.1"},
			expected: List{"example.1"},
			wantErr:  false,
		},
		{
			name:     "All numeric labels allowed",
			domains:  []string{"123.456"},
			expected: List{"123.456"},
			wantErr:  false,
		},
		{
			name:     "Single numeric label allowed",
			domains:  []string{"123"},
			expected: List{"123"},
			wantErr:  false,
		},
		{
			name:     "Valid domain with double hyphen",
			domains:  []string{"test--example.com"},
			expected: List{"test--example.com"},
			wantErr:  false,
		},
		{
			name:     "Invalid leading hyphen",
			domains:  []string{"-example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid trailing hyphen",
			domains:  []string{"example.com-"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid leading dot",
			domains:  []string{".com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid dot only",
			domains:  []string{"."},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid double dot",
			domains:  []string{"example..com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid special characters",
			domains:  []string{"example?,.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid space in domain",
			domains:  []string{"space .example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid trailing space",
			domains:  []string{"example.com "},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Multiple domains valid and invalid",
			domains:  []string{"google.com", "invalid,nbdomain.com", "münchen.de"},
			expected: List{"google.com"},
			wantErr:  true,
		},
		{
			name:     "Valid wildcard domain",
			domains:  []string{"*.example.com"},
			expected: List{"*.example.com"},
			wantErr:  false,
		},
		{
			name:     "Wildcard with dot domain",
			domains:  []string{".*.example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Wildcard with dot domain",
			domains:  []string{".*.example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid wildcard domain",
			domains:  []string{"a.*.example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Valid 63 char label (max)",
			domains:  []string{label63 + ".com"},
			expected: List{Domain(label63 + ".com")},
			wantErr:  false,
		},
		{
			name:     "Invalid 64 char label (exceeds max)",
			domains:  []string{label64 + ".com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Valid 253 char domain (max)",
			domains:  []string{strings.Repeat("a.", 126) + "a"},
			expected: List{Domain(strings.Repeat("a.", 126) + "a")},
			wantErr:  false,
		},
		{
			name:     "Invalid 254+ char domain (exceeds max)",
			domains:  []string{strings.Repeat("ab.", 85)},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateDomains(tt.domains)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, got, tt.expected)
		})
	}
}

func TestValidateDomainsList(t *testing.T) {
	validDomains := make([]string, maxDomains)
	for i := range maxDomains {
		validDomains[i] = fmt.Sprintf("example%d.com", i)
	}

	tests := []struct {
		name    string
		domains []string
		wantErr bool
	}{
		{
			name:    "Empty list",
			domains: nil,
			wantErr: false,
		},
		{
			name:    "Single valid ASCII domain",
			domains: []string{"sub.ex-ample.com"},
			wantErr: false,
		},
		{
			name:    "Uppercase domain accepted",
			domains: []string{"EXAMPLE.COM"},
			wantErr: false,
		},
		{
			name:    "Single letter TLD",
			domains: []string{"example.x"},
			wantErr: false,
		},
		{
			name:    "Two letter domain labels",
			domains: []string{"a.b"},
			wantErr: false,
		},
		{
			name:    "Single character domain",
			domains: []string{"x"},
			wantErr: false,
		},
		{
			name:    "Wildcard with single letter TLD",
			domains: []string{"*.x"},
			wantErr: false,
		},
		{
			name:    "Multi-level with single letter labels",
			domains: []string{"a.b.c"},
			wantErr: false,
		},
		// Numeric TLDs are allowed for internal/private DNS use cases.
		{
			name:    "Numeric TLD allowed",
			domains: []string{"example.123"},
			wantErr: false,
		},
		{
			name:    "Single digit TLD allowed",
			domains: []string{"example.1"},
			wantErr: false,
		},
		{
			name:    "All numeric labels allowed",
			domains: []string{"123.456"},
			wantErr: false,
		},
		{
			name:    "Single numeric label allowed",
			domains: []string{"123"},
			wantErr: false,
		},
		{
			name:    "Underscores in labels",
			domains: []string{"_jabber._tcp.gmail.com"},
			wantErr: false,
		},
		{
			// Unlike ValidateDomains (which converts to punycode),
			// ValidateDomainsStrSlice will fail on non-ASCII domain chars.
			name:    "Unicode domain fails (no punycode conversion)",
			domains: []string{"münchen.de"},
			wantErr: true,
		},
		{
			name:    "Invalid domain format - leading dash",
			domains: []string{"-example.com"},
			wantErr: true,
		},
		{
			name:    "Invalid domain format - trailing dash",
			domains: []string{"example-.com"},
			wantErr: true,
		},
		{
			name:    "Multiple domains with a valid one, then invalid",
			domains: []string{"google.com", "invalid_domain.com-"},
			wantErr: true,
		},
		{
			name:    "Valid wildcard domain",
			domains: []string{"*.example.com"},
			wantErr: false,
		},
		{
			name:    "Wildcard with leading dot - invalid",
			domains: []string{".*.example.com"},
			wantErr: true,
		},
		{
			name:    "Invalid wildcard with multiple asterisks",
			domains: []string{"a.*.example.com"},
			wantErr: true,
		},
		{
			name:    "Exactly maxDomains items (valid)",
			domains: validDomains,
			wantErr: false,
		},
		{
			name:    "Exceeds maxDomains items",
			domains: append(validDomains, "extra.com"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainsList(tt.domains)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
