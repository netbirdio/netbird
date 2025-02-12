package domain

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDomains(t *testing.T) {
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
			name:     "Invalid domain format",
			domains:  []string{"-example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid domain format 2",
			domains:  []string{"example.com-"},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateDomains(tt.domains)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, got, tt.expected)
		})
	}
}

// TestValidateDomainsStrSlice tests the ValidateDomainsStrSlice function.
func TestValidateDomainsStrSlice(t *testing.T) {
	// Generate a slice of valid domains up to maxDomains
	validDomains := make([]string, maxDomains)
	for i := 0; i < maxDomains; i++ {
		validDomains[i] = fmt.Sprintf("example%d.com", i)
	}

	tests := []struct {
		name     string
		domains  []string
		expected []string
		wantErr  bool
	}{
		{
			name:     "Empty list",
			domains:  nil,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Single valid ASCII domain",
			domains:  []string{"sub.ex-ample.com"},
			expected: []string{"sub.ex-ample.com"},
			wantErr:  false,
		},
		{
			name:     "Underscores in labels",
			domains:  []string{"_jabber._tcp.gmail.com"},
			expected: []string{"_jabber._tcp.gmail.com"},
			wantErr:  false,
		},
		{
			// Unlike ValidateDomains (which converts to punycode),
			// ValidateDomainsStrSlice will fail on non-ASCII domain chars.
			name:     "Unicode domain fails (no punycode conversion)",
			domains:  []string{"münchen.de"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid domain format - leading dash",
			domains:  []string{"-example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid domain format - trailing dash",
			domains:  []string{"example-.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			// The function stops on the first invalid domain and returns an error,
			// so only the first domain is definitely valid, but the second is invalid.
			// We verify that the error is returned (we do not expect a partially filled list).
			name:     "Multiple domains with a valid one, then invalid",
			domains:  []string{"google.com", "invalid_domain.com-"},
			expected: []string{"google.com"},
			wantErr:  true,
		},
		{
			name:     "Valid wildcard domain",
			domains:  []string{"*.example.com"},
			expected: []string{"*.example.com"},
			wantErr:  false,
		},
		{
			name:     "Wildcard with leading dot - invalid",
			domains:  []string{".*.example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid wildcard with multiple asterisks",
			domains:  []string{"a.*.example.com"},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Exactly maxDomains items (valid)",
			domains:  validDomains,
			expected: validDomains,
			wantErr:  false,
		},
		{
			name:     "Exceeds maxDomains items",
			domains:  append(validDomains, "extra.com"),
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateDomainsStrSlice(tt.domains)
			// Check if we got an error where expected
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Compare the returned domains to what we expect
			// Note: in the case of an error, you might not care about the partial result.
			// If you do, you can change the assertion logic accordingly.
			assert.Equal(t, tt.expected, got)
		})
	}
}
