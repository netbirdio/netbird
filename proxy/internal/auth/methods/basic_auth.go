package methods

import (
	"crypto/subtle"
	"net/http"
)

// BasicAuthConfig holds HTTP Basic authentication settings
type BasicAuthConfig struct {
	Username string
	Password string
}

// Validate checks Basic Auth credentials from the request
func (c *BasicAuthConfig) Validate(r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(c.Username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(c.Password)) == 1

	return usernameMatch && passwordMatch
}
