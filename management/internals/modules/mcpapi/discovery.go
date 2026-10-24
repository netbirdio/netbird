package mcpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
)

const (
	// authPath holds the authorization server's endpoints, relative to the API router. It
	// sits under the MCP endpoint so everything MCP-specific shares one prefix.
	authPath = Path + "/auth"

	// registrationPath is the RFC 7591 registration endpoint, relative to the API router.
	registrationPath = authPath + "/register"

	// ProtectedResourcePath serves the RFC 9728 protected resource metadata for the MCP
	// endpoint. MCP clients read it to learn which authorization server issues tokens.
	ProtectedResourcePath = "/.well-known/oauth-protected-resource" + apiPrefix + Path

	// resourceMetadataAPIPath serves the same document under the API router, relative to it.
	// The challenge points clients here: reverse proxies in front of self-hosted management
	// often forward only /api to it, and RFC 9728 section 5.1 lets the challenge name any URL.
	resourceMetadataAPIPath = Path + "/.well-known/oauth-protected-resource"

	// authIssuerPath is the issuer path of the broker, management's own authorization server.
	authIssuerPath = apiPrefix + authPath

	// Metadata paths clients derive from the issuer: RFC 8414 and OIDC path insertion on the
	// root router, where clients look for them, and the OIDC path-appended form under the API
	// router.
	authServerMetadataPath     = "/.well-known/oauth-authorization-server" + authIssuerPath
	openIDConfigurationPath    = "/.well-known/openid-configuration" + authIssuerPath
	openIDConfigurationAPIPath = authPath + "/.well-known/openid-configuration"

	apiPrefix = "/api"
)

// FlowConfig is the identity provider's PKCE flow the broker logs users in with: the same
// client and endpoints agents use for an SSO login.
type FlowConfig struct {
	ClientID              string
	Audience              string
	AuthorizationEndpoint string
	TokenEndpoint         string
	Scope                 string
	// UseIDToken forwards the ID token instead of the access token for validation, for
	// identity providers whose access tokens are not JWTs.
	UseIDToken bool
}

// FlowFromConfig picks the flow the way the gRPC handler does: the embedded IdP wins when it
// is enabled, otherwise the configured PKCE flow is used. It returns nil when neither is
// available.
func FlowFromConfig(cfg *nbconfig.Config, provider idp.OAuthConfigProvider) *FlowConfig {
	if provider != nil {
		return &FlowConfig{
			ClientID:              provider.GetCLIClientID(),
			Audience:              provider.GetCLIClientID(),
			AuthorizationEndpoint: provider.GetAuthorizationEndpoint(),
			TokenEndpoint:         provider.GetTokenEndpoint(),
			Scope:                 provider.GetDefaultScopes(),
		}
	}

	if cfg == nil || cfg.PKCEAuthorizationFlow == nil {
		return nil
	}

	pc := cfg.PKCEAuthorizationFlow.ProviderConfig
	return &FlowConfig{
		ClientID:              pc.ClientID,
		Audience:              pc.Audience,
		AuthorizationEndpoint: pc.AuthorizationEndpoint,
		TokenEndpoint:         pc.TokenEndpoint,
		Scope:                 pc.Scope,
		UseIDToken:            pc.UseIDToken,
	}
}

// FlowClientSecret returns the client secret of the configured PKCE flow, for identity
// providers whose client is confidential. The embedded IdP's client is public.
func FlowClientSecret(cfg *nbconfig.Config, provider idp.OAuthConfigProvider) string {
	if provider != nil || cfg == nil || cfg.PKCEAuthorizationFlow == nil {
		return ""
	}
	return cfg.PKCEAuthorizationFlow.ProviderConfig.ClientSecret //nolint:staticcheck
}

// protectedResource is the RFC 9728 metadata document for the MCP endpoint.
type protectedResource struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
}

// clientRegistration carries the RFC 7591 fields management reads and echoes back.
type clientRegistration struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
	Scope        string   `json:"scope,omitempty"`
}

// clientRegistrationResponse is the RFC 7591 success response. Clients are public, so there
// is never a secret.
type clientRegistrationResponse struct {
	clientRegistration
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// validateRedirectURI accepts https anywhere and http only on a loopback host, the rule
// OAuth 2.1 sets for native and web clients.
func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("redirect uri %q is not an absolute URL", raw)
	}
	if u.Fragment != "" || u.User != nil {
		return fmt.Errorf("redirect uri %q must not carry a fragment or user info", raw)
	}
	// The consent page shows this host to the user; a look-alike Unicode host would pass for a real one.
	for i := 0; i < len(u.Host); i++ {
		if u.Host[i] >= 0x80 {
			return fmt.Errorf("redirect uri %q must use an ASCII host name", raw)
		}
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("redirect uri %q must use https unless it is a loopback address", raw)
	default:
		return fmt.Errorf("redirect uri %q must use https or loopback http", raw)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// externalBaseURL rebuilds the scheme and host the client connected with, honoring the
// forwarding headers a TLS-terminating proxy sets.
func externalBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ","); strings.TrimSpace(proto) != "" {
		scheme = strings.TrimSpace(proto)
	}

	host := r.Host
	if fwd, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Host"), ","); strings.TrimSpace(fwd) != "" {
		host = strings.TrimSpace(fwd)
	}
	return scheme + "://" + host
}
