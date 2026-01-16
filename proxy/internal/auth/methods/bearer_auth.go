package methods

// BearerConfig holds JWT/OAuth/OIDC bearer token authentication settings
// The actual OIDC/JWT configuration comes from the global proxy Config.OIDCConfig
// This just enables Bearer auth for a specific route
type BearerConfig struct {
	Enabled bool
}
