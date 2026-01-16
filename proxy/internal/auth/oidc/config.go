package oidc

// Config holds the global OIDC/OAuth configuration
type Config struct {
	ProviderURL  string   `env:"NB_OIDC_PROVIDER_URL" json:"provider_url"`
	ClientID     string   `env:"NB_OIDC_CLIENT_ID" json:"client_id"`
	ClientSecret string   `env:"NB_OIDC_CLIENT_SECRET" json:"client_secret"`
	RedirectURL  string   `env:"NB_OIDC_REDIRECT_URL" json:"redirect_url"`
	Scopes       []string `env:"NB_OIDC_SCOPES" json:"scopes"`

	JWTKeysLocation             string   `env:"NB_OIDC_JWT_KEYS_LOCATION" json:"jwt_keys_location"`
	JWTIssuer                   string   `env:"NB_OIDC_JWT_ISSUER" json:"jwt_issuer"`
	JWTAudience                 []string `env:"NB_OIDC_JWT_AUDIENCE" json:"jwt_audience"`
	JWTIdpSignkeyRefreshEnabled bool     `env:"NB_OIDC_JWT_IDP_SIGNKEY_REFRESH_ENABLED" json:"jwt_idp_signkey_refresh_enabled"`

	SessionCookieName string `env:"NB_OIDC_SESSION_COOKIE_NAME" json:"session_cookie_name"`
}
