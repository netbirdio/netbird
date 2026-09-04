package playground

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		headers http.Header
		bodyLen int
		wantErr string
	}{
		{
			name:    "valid provider request",
			method:  http.MethodPost,
			path:    "/v1/chat/completions?beta=true",
			headers: http.Header{"Content-Type": {"application/json"}, "Anthropic-Version": {"2023-06-01"}},
		},
		{name: "unsupported method", method: http.MethodPut, path: "/v1/models", wantErr: "method must be GET or POST"},
		{name: "absolute URL", method: http.MethodGet, path: "https://example.com/v1/models", wantErr: "path must be origin-form"},
		{name: "missing leading slash", method: http.MethodGet, path: "v1/models", wantErr: "parse request path"},
		{name: "oversized body", method: http.MethodPost, path: "/v1/chat", bodyLen: MaxRequestBodyBytes + 1, wantErr: "body exceeds"},
		{name: "authorization header", method: http.MethodGet, path: "/v1/models", headers: http.Header{"Authorization": {"Bearer secret"}}, wantErr: "protected"},
		{name: "forwarded header", method: http.MethodGet, path: "/v1/models", headers: http.Header{"X-Forwarded-For": {"127.0.0.1"}}, wantErr: "protected"},
		{name: "invalid header value", method: http.MethodGet, path: "/v1/models", headers: http.Header{"OpenAI-Beta": {"bad\nvalue"}}, wantErr: "invalid value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRequest(test.method, test.path, test.headers, test.bodyLen)
			if test.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			if assert.Error(t, err) {
				assert.True(t, strings.Contains(err.Error(), test.wantErr), "Error should contain %q: %v", test.wantErr, err)
			}
		})
	}
}
