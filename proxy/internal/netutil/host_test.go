package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"Example.COM.":          "example.com",
		"Example.COM.:443":      "example.com",
		"b\u00fccher.example":   "xn--bcher-kva.example",
		"[2001:db8::1]:8443":    "2001:db8::1",
		"  APP.Example.TEST.  ": "app.example.test",
	}
	for input, want := range tests {
		assert.Equal(t, want, NormalizeHost(input), input)
	}
}

func TestNormalizeAuthority(t *testing.T) {
	assert.Equal(t, "example.com:8443", NormalizeAuthority("Example.COM.:8443"))
	assert.Equal(t, "example.com", NormalizeAuthority("Example.COM."))
	assert.Equal(t, "[2001:db8::1]:8443", NormalizeAuthority("[2001:DB8::1]:8443"))
}
