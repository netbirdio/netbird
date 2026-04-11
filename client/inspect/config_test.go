package inspect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/domain"
)

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		target  string
		want    bool
	}{
		{
			name:    "exact match",
			pattern: "example.com",
			target:  "example.com",
			want:    true,
		},
		{
			name:    "exact no match",
			pattern: "example.com",
			target:  "other.com",
			want:    false,
		},
		{
			name:    "wildcard matches subdomain",
			pattern: "*.example.com",
			target:  "foo.example.com",
			want:    true,
		},
		{
			name:    "wildcard matches deep subdomain",
			pattern: "*.example.com",
			target:  "a.b.c.example.com",
			want:    true,
		},
		{
			name:    "wildcard does not match base",
			pattern: "*.example.com",
			target:  "example.com",
			want:    false,
		},
		{
			name:    "wildcard does not match unrelated",
			pattern: "*.example.com",
			target:  "foo.other.com",
			want:    false,
		},
		{
			name:    "case insensitive exact match",
			pattern: "Example.COM",
			target:  "example.com",
			want:    true,
		},
		{
			name:    "case insensitive wildcard match",
			pattern: "*.Example.COM",
			target:  "FOO.example.com",
			want:    true,
		},
		{
			name:    "wildcard does not match partial suffix",
			pattern: "*.example.com",
			target:  "notexample.com",
			want:    false,
		},
		{
			name:    "unicode domain punycode match",
			pattern: "*.münchen.de",
			target:  "sub.xn--mnchen-3ya.de",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := domain.FromString(tt.pattern)
			require.NoError(t, err)

			target, err := domain.FromString(tt.target)
			require.NoError(t, err)

			got := MatchDomain(pattern, target)
			assert.Equal(t, tt.want, got)
		})
	}
}
