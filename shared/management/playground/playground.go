// Package playground defines the shared Agent Network playground wire limits.
package playground

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	// MaxRequestBodyBytes is the largest playground request body.
	MaxRequestBodyBytes = 1 << 20
	// MaxResponseBodyBytes is the largest playground response returned to Management.
	MaxResponseBodyBytes = 8 << 20
	// ResponseChunkBytes is the maximum response body frame size.
	ResponseChunkBytes = 64 << 10
)

var protectedHeaders = map[string]struct{}{
	"authorization":       {},
	"connection":          {},
	"content-length":      {},
	"cookie":              {},
	"forwarded":           {},
	"host":                {},
	"keep-alive":          {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// ValidateRequest validates an untrusted provider-native playground request.
func ValidateRequest(method, path string, headers http.Header, bodyBytes int) error {
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("method must be GET or POST")
	}
	if bodyBytes < 0 || bodyBytes > MaxRequestBodyBytes {
		return fmt.Errorf("body exceeds %d bytes", MaxRequestBodyBytes)
	}

	parsed, err := url.ParseRequestURI(path)
	if err != nil {
		return fmt.Errorf("parse request path: %w", err)
	}
	if !strings.HasPrefix(path, "/") || parsed.IsAbs() || parsed.Host != "" {
		return fmt.Errorf("path must be origin-form")
	}

	for name, values := range headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("invalid header name %q", name)
		}
		lowerName := strings.ToLower(name)
		if _, ok := protectedHeaders[lowerName]; ok || strings.HasPrefix(lowerName, "x-forwarded-") {
			return fmt.Errorf("header %q is protected", name)
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return fmt.Errorf("invalid value for header %q", name)
			}
		}
	}
	return nil
}
