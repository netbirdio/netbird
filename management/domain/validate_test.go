package domain

import (
	"testing"

	"github.com/magiconair/properties/assert"
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
