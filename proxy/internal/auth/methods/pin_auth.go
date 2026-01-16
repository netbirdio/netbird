package methods

import (
	"crypto/subtle"
	"net/http"
)

const (
	// DefaultPINHeader is the default header name for PIN authentication
	DefaultPINHeader = "X-PIN"
)

// PINConfig holds PIN authentication settings
type PINConfig struct {
	PIN    string
	Header string
}

// Validate checks PIN from the request header
func (c *PINConfig) Validate(r *http.Request) bool {
	header := c.Header
	if header == "" {
		header = DefaultPINHeader
	}

	providedPIN := r.Header.Get(header)
	if providedPIN == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(providedPIN), []byte(c.PIN)) == 1
}
