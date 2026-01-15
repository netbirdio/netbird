package oidc

// Config holds the global OIDC/OAuth configuration
type Config struct {
	// OIDC Provider settings
	ProviderURL  string   `env:"NB_OIDC_PROVIDER_URL" json:"provider_url"`   // Identity provider URL (e.g., "https://accounts.google.com")
	ClientID     string   `env:"NB_OIDC_CLIENT_ID" json:"client_id"`         // OAuth client ID
	ClientSecret string   `env:"NB_OIDC_CLIENT_SECRET" json:"client_secret"` // OAuth client secret (empty for public clients)
	RedirectURL  string   `env:"NB_OIDC_REDIRECT_URL" json:"redirect_url"`   // Redirect URL after auth (e.g., "http://localhost:54321/auth/callback")
	Scopes       []string `env:"NB_OIDC_SCOPES" json:"scopes"`               // Requested scopes (default: ["openid", "profile", "email"])

	// JWT Validation settings
	JWTKeysLocation             string   `env:"NB_OIDC_JWT_KEYS_LOCATION" json:"jwt_keys_location"`                             // JWKS URL for fetching public keys
	JWTIssuer                   string   `env:"NB_OIDC_JWT_ISSUER" json:"jwt_issuer"`                                           // Expected issuer claim
	JWTAudience                 []string `env:"NB_OIDC_JWT_AUDIENCE" json:"jwt_audience"`                                       // Expected audience claims
	JWTIdpSignkeyRefreshEnabled bool     `env:"NB_OIDC_JWT_IDP_SIGNKEY_REFRESH_ENABLED" json:"jwt_idp_signkey_refresh_enabled"` // Enable automatic refresh of signing keys

	// Session settings
	SessionCookieName string `env:"NB_OIDC_SESSION_COOKIE_NAME" json:"session_cookie_name"` // Cookie name for storing session (default: "auth_session")
}
