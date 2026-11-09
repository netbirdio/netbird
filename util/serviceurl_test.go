package util

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSameServiceURLSpellings(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		// One endpoint, written several ways.
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com:443", want: true},
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com/", want: true},
		{a: "https://mgmt.example.com/", b: "https://mgmt.example.com:443/", want: true},
		{a: "https://MGMT.example.com", b: "https://mgmt.example.com", want: true},
		{a: "https://mgmt.example.com:0443", b: "https://mgmt.example.com:443", want: true},
		{a: "http://mgmt.example.com", b: "http://mgmt.example.com:80", want: true},
		{a: "HTTPS://mgmt.example.com", b: "https://mgmt.example.com", want: true},

		// Different endpoints.
		{a: "https://mgmt.example.com", b: "http://mgmt.example.com", want: false},
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com:8443", want: false},
		{a: "https://mgmt.example.com", b: "https://other.example.com", want: false},
		{a: "https://mgmt.example.com", b: "https://mgmt.example.com/other", want: false},

		// Unparseable input falls back to string equality.
		{a: "mgmt.example.com", b: "mgmt.example.com", want: true},
		{a: "mgmt.example.com", b: "https://mgmt.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			assert.Equal(t, tt.want, SameServiceURLStrings(tt.a, tt.b))
			assert.Equal(t, tt.want, SameServiceURLStrings(tt.b, tt.a), "the comparison must be symmetric")
		})
	}
}

// The parsed form is the primitive the string form delegates to, so it must
// answer the same for a spelling that only the parser can tell apart.
func TestSameServiceURLParsed(t *testing.T) {
	parse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.ParseRequestURI(raw)
		require.NoError(t, err)
		return u
	}

	assert.True(t, SameServiceURL(parse("https://mgmt.example.com:0443/"), parse("https://MGMT.example.com")))
	assert.False(t, SameServiceURL(parse("https://mgmt.example.com"), parse("https://mgmt.example.com:8443")))

	assert.True(t, SameServiceURL(nil, nil), "two absent URLs are the same absence")
	assert.False(t, SameServiceURL(nil, parse("https://mgmt.example.com")))
}

func TestServiceURLPort(t *testing.T) {
	parse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.ParseRequestURI(raw)
		require.NoError(t, err)
		return u
	}

	assert.Equal(t, "443", ServiceURLPort(parse("https://mgmt.example.com")))
	assert.Equal(t, "80", ServiceURLPort(parse("http://mgmt.example.com")))
	assert.Equal(t, "443", ServiceURLPort(parse("https://mgmt.example.com:0443")))
	assert.Equal(t, "8443", ServiceURLPort(parse("https://mgmt.example.com:8443")))
}
