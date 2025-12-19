package oidcprovider

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// OIDCClient wraps the database Client model and implements op.Client interface
type OIDCClient struct {
	client        *Client
	loginURL      func(string) string
	redirectURIs  []string
	grantTypes    []oidc.GrantType
	responseTypes []oidc.ResponseType
}

// NewOIDCClient creates an OIDCClient from a database Client
func NewOIDCClient(client *Client, loginURL func(string) string) *OIDCClient {
	return &OIDCClient{
		client:        client,
		loginURL:      loginURL,
		redirectURIs:  ParseJSONArray(client.RedirectURIs),
		grantTypes:    parseGrantTypes(client.GrantTypes),
		responseTypes: parseResponseTypes(client.ResponseTypes),
	}
}

// GetID returns the client ID
func (c *OIDCClient) GetID() string {
	return c.client.ID
}

// RedirectURIs returns the registered redirect URIs
func (c *OIDCClient) RedirectURIs() []string {
	return c.redirectURIs
}

// PostLogoutRedirectURIs returns the registered post-logout redirect URIs
func (c *OIDCClient) PostLogoutRedirectURIs() []string {
	return ParseJSONArray(c.client.PostLogoutURIs)
}

// ApplicationType returns the application type (native, web, user_agent)
func (c *OIDCClient) ApplicationType() op.ApplicationType {
	switch c.client.ApplicationType {
	case "native":
		return op.ApplicationTypeNative
	case "web":
		return op.ApplicationTypeWeb
	case "user_agent":
		return op.ApplicationTypeUserAgent
	default:
		return op.ApplicationTypeWeb
	}
}

// AuthMethod returns the authentication method
func (c *OIDCClient) AuthMethod() oidc.AuthMethod {
	switch c.client.AuthMethod {
	case "none":
		return oidc.AuthMethodNone
	case "client_secret_basic":
		return oidc.AuthMethodBasic
	case "client_secret_post":
		return oidc.AuthMethodPost
	case "private_key_jwt":
		return oidc.AuthMethodPrivateKeyJWT
	default:
		return oidc.AuthMethodNone
	}
}

// ResponseTypes returns the allowed response types
func (c *OIDCClient) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

// GrantTypes returns the allowed grant types
func (c *OIDCClient) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

// LoginURL returns the login URL for this client
func (c *OIDCClient) LoginURL(authRequestID string) string {
	if c.loginURL != nil {
		return c.loginURL(authRequestID)
	}
	return "/login?authRequestID=" + authRequestID
}

// AccessTokenType returns the access token type
func (c *OIDCClient) AccessTokenType() op.AccessTokenType {
	switch c.client.AccessTokenType {
	case "jwt":
		return op.AccessTokenTypeJWT
	default:
		return op.AccessTokenTypeBearer
	}
}

// IDTokenLifetime returns the ID token lifetime
func (c *OIDCClient) IDTokenLifetime() time.Duration {
	if c.client.IDTokenLifetime > 0 {
		return time.Duration(c.client.IDTokenLifetime) * time.Second
	}
	return time.Hour // default 1 hour
}

// DevMode returns whether the client is in development mode
func (c *OIDCClient) DevMode() bool {
	return c.client.DevMode
}

// RestrictAdditionalIdTokenScopes returns any restricted scopes for ID tokens
func (c *OIDCClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

// RestrictAdditionalAccessTokenScopes returns any restricted scopes for access tokens
func (c *OIDCClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

// IsScopeAllowed checks if a scope is allowed for this client
func (c *OIDCClient) IsScopeAllowed(scope string) bool {
	// Allow all standard OIDC scopes
	switch scope {
	case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeAddress, oidc.ScopeOfflineAccess:
		return true
	}
	return true // Allow custom scopes as well
}

// IDTokenUserinfoClaimsAssertion returns whether userinfo claims should be included in ID token
func (c *OIDCClient) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

// ClockSkew returns the allowed clock skew for this client
func (c *OIDCClient) ClockSkew() time.Duration {
	if c.client.ClockSkew > 0 {
		return time.Duration(c.client.ClockSkew) * time.Second
	}
	return 0
}

// Helper functions for parsing grant types and response types

func parseGrantTypes(jsonStr string) []oidc.GrantType {
	types := ParseJSONArray(jsonStr)
	if len(types) == 0 {
		// Default grant types
		return []oidc.GrantType{
			oidc.GrantTypeCode,
			oidc.GrantTypeRefreshToken,
		}
	}

	result := make([]oidc.GrantType, 0, len(types))
	for _, t := range types {
		switch t {
		case "authorization_code":
			result = append(result, oidc.GrantTypeCode)
		case "refresh_token":
			result = append(result, oidc.GrantTypeRefreshToken)
		case "client_credentials":
			result = append(result, oidc.GrantTypeClientCredentials)
		case "urn:ietf:params:oauth:grant-type:device_code":
			result = append(result, oidc.GrantTypeDeviceCode)
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			result = append(result, oidc.GrantTypeTokenExchange)
		}
	}
	return result
}

func parseResponseTypes(jsonStr string) []oidc.ResponseType {
	types := ParseJSONArray(jsonStr)
	if len(types) == 0 {
		// Default response types
		return []oidc.ResponseType{oidc.ResponseTypeCode}
	}

	result := make([]oidc.ResponseType, 0, len(types))
	for _, t := range types {
		switch t {
		case "code":
			result = append(result, oidc.ResponseTypeCode)
		case "id_token":
			result = append(result, oidc.ResponseTypeIDToken)
		}
	}
	return result
}

// CreateNativeClient creates a native client configuration (for CLI/mobile apps with PKCE)
func CreateNativeClient(id, name string, redirectURIs []string) *Client {
	return &Client{
		ID:              id,
		Name:            name,
		RedirectURIs:    ToJSONArray(redirectURIs),
		ApplicationType: "native",
		AuthMethod:      "none", // Public client
		ResponseTypes:   ToJSONArray([]string{"code"}),
		GrantTypes:      ToJSONArray([]string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"}),
		AccessTokenType: "bearer",
		DevMode:         true,
		IDTokenLifetime: 3600,
	}
}

// CreateWebClient creates a web client configuration (for SPAs/web apps)
func CreateWebClient(id, secret, name string, redirectURIs []string) *Client {
	return &Client{
		ID:              id,
		Secret:          secret,
		Name:            name,
		RedirectURIs:    ToJSONArray(redirectURIs),
		ApplicationType: "web",
		AuthMethod:      "client_secret_basic",
		ResponseTypes:   ToJSONArray([]string{"code"}),
		GrantTypes:      ToJSONArray([]string{"authorization_code", "refresh_token"}),
		AccessTokenType: "bearer",
		DevMode:         false,
		IDTokenLifetime: 3600,
	}
}

// CreateSPAClient creates a Single Page Application client configuration (public client for SPAs)
func CreateSPAClient(id, name string, redirectURIs []string) *Client {
	return &Client{
		ID:              id,
		Name:            name,
		RedirectURIs:    ToJSONArray(redirectURIs),
		ApplicationType: "user_agent",
		AuthMethod:      "none", // Public client for SPA
		ResponseTypes:   ToJSONArray([]string{"code"}),
		GrantTypes:      ToJSONArray([]string{"authorization_code", "refresh_token"}),
		AccessTokenType: "bearer",
		DevMode:         true,
		IDTokenLifetime: 3600,
	}
}
