package auth

import "github.com/netbirdio/netbird/proxy/internal/auth/methods"

// Config holds the authentication configuration for a route
// Only ONE auth method should be configured per route
type Config struct {
	// HTTP Basic authentication (username/password)
	BasicAuth *methods.BasicAuthConfig

	// PIN authentication
	PIN *methods.PINConfig

	// Bearer token with JWT validation and OAuth/OIDC flow
	// When enabled, uses the global OIDCConfig from proxy Config
	Bearer *methods.BearerConfig
}

// IsEmpty returns true if no auth methods are configured
func (c *Config) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.BasicAuth == nil && c.PIN == nil && c.Bearer == nil
}
