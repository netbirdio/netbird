package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripUpstreamPathPrefix(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		prefix string
		want   string
	}{
		{"strips matching namespace prefix", "/bedrock/model/x/invoke", "/bedrock", "/model/x/invoke"},
		{"no-op when prefix absent", "/model/x/invoke", "/bedrock", "/model/x/invoke"},
		{"no-op on empty prefix", "/bedrock/model/x/invoke", "", "/bedrock/model/x/invoke"},
		{"no-op on non-segment match", "/bedrockfoo/model/x", "/bedrock", "/bedrockfoo/model/x"},
		{"bare prefix collapses to root", "/bedrock", "/bedrock", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.path, nil)
			stripUpstreamPathPrefix(r, tc.prefix)
			assert.Equal(t, tc.want, r.URL.Path, "stripped path for %q", tc.path)
		})
	}
}
