package config

import (
	"fmt"
	"net/netip"

	"github.com/dexidp/dex/storage"
	"github.com/google/uuid"
	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/client/common"
	"github.com/netbirdio/netbird/util"
)

type (
	// Protocol type
	Protocol string

	// Provider authorization flow type
	Provider string
)

const (
	UDP   Protocol = "udp"
	DTLS  Protocol = "dtls"
	TCP   Protocol = "tcp"
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
	NONE  Provider = "none"
)

const (
	// DefaultDeviceAuthFlowScope defines the bare minimum scope to request in the device authorization flow
	DefaultDeviceAuthFlowScope string = "openid"
)

var MgmtConfigPath string

// Config of the Management service
type Config struct {
	Stuns      []*Host
	TURNConfig *TURNConfig
	Relay      *Relay
	Signal     *Host

	Datadir                string
	DataStoreEncryptionKey string

	HttpConfig *HttpServerConfig

	IdpManagerConfig *idp.Config

	DeviceAuthorizationFlow *DeviceAuthorizationFlow

	PKCEAuthorizationFlow *PKCEAuthorizationFlow

	StoreConfig StoreConfig

	ReverseProxy ReverseProxy

	// disable default all-to-all policy
	DisableDefaultPolicy bool

	// EmbeddedIdP contains configuration for the embedded Dex OIDC provider.
	// When set, Dex will be embedded in the management server and serve requests at /oauth2/
	EmbeddedIdP *EmbeddedIdPConfig
}

// EmbeddedIdPConfig contains configuration for the embedded Dex OIDC identity provider
type EmbeddedIdPConfig struct {
	// Enabled indicates whether the embedded IDP is enabled
	Enabled bool
	// Issuer is the OIDC issuer URL (e.g., "http://localhost:3002/oauth2")
	Issuer string
	// Storage configuration for the IdP database
	Storage EmbeddedStorageConfig
	// DashboardRedirectURIs are the OAuth2 redirect URIs for the dashboard client
	DashboardRedirectURIs []string
	// DashboardRedirectURIs are the OAuth2 redirect URIs for the dashboard client
	CLIRedirectURIs []string
	// Owner is the initial owner/admin user (optional, can be nil)
	Owner *OwnerConfig
	// SignKeyRefreshEnabled enables automatic key rotation for signing keys
	SignKeyRefreshEnabled bool
}

// EmbeddedStorageConfig holds storage configuration for the embedded IdP.
type EmbeddedStorageConfig struct {
	// Type is the storage type (currently only "sqlite3" is supported)
	Type string
	// Config contains type-specific configuration
	Config EmbeddedStorageTypeConfig
}

// EmbeddedStorageTypeConfig contains type-specific storage configuration.
type EmbeddedStorageTypeConfig struct {
	// File is the path to the SQLite database file (for sqlite3 type)
	File string
}

// OwnerConfig represents the initial owner/admin user for the embedded IdP.
type OwnerConfig struct {
	// Email is the user's email address (required)
	Email string
	// Hash is the bcrypt hash of the user's password (required)
	Hash string
	// Username is the display name for the user (optional, defaults to email)
	Username string
}

// GetAuthAudiences returns the audience from the http config and device authorization flow config
func (c Config) GetAuthAudiences() []string {
	audiences := []string{c.HttpConfig.AuthAudience}

	if c.HttpConfig.ExtraAuthAudience != "" {
		audiences = append(audiences, c.HttpConfig.ExtraAuthAudience)
	}

	if c.DeviceAuthorizationFlow != nil && c.DeviceAuthorizationFlow.ProviderConfig.Audience != "" {
		audiences = append(audiences, c.DeviceAuthorizationFlow.ProviderConfig.Audience)
	}

	return audiences
}

// ToYAMLConfig converts EmbeddedIdPConfig to dex.YAMLConfig.
func (c *EmbeddedIdPConfig) ToYAMLConfig() (*dex.YAMLConfig, error) {
	if c.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if c.Storage.Type == "" {
		c.Storage.Type = "sqlite3"
	}
	if c.Storage.Type == "sqlite3" && c.Storage.Config.File == "" {
		return nil, fmt.Errorf("storage file is required for sqlite3")
	}

	cfg := &dex.YAMLConfig{
		Issuer: c.Issuer,
		Storage: dex.Storage{
			Type: c.Storage.Type,
			Config: map[string]interface{}{
				"file": c.Storage.Config.File,
			},
		},
		Web: dex.Web{
			AllowedOrigins: []string{"*"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
		},
		OAuth2: dex.OAuth2{
			SkipApprovalScreen: true,
		},
		Frontend: dex.Frontend{
			Issuer: "NetBird",
			Theme:  "light",
		},
		EnablePasswordDB: true,
		StaticClients: []storage.Client{
			{
				ID:           "netbird-dashboard",
				Name:         "NetBird Dashboard",
				Public:       true,
				RedirectURIs: c.DashboardRedirectURIs,
			},
			{
				ID:           "netbird-cli",
				Name:         "NetBird CLI",
				Public:       true,
				RedirectURIs: c.CLIRedirectURIs,
			},
		},
	}

	// Add owner user if provided
	if c.Owner != nil && c.Owner.Email != "" && c.Owner.Hash != "" {
		username := c.Owner.Username
		if username == "" {
			username = c.Owner.Email
		}
		cfg.StaticPasswords = []dex.Password{
			{
				Email:    c.Owner.Email,
				Hash:     []byte(c.Owner.Hash),
				Username: username,
				UserID:   uuid.New().String(),
			},
		}
	}

	return cfg, nil
}

// TURNConfig is a config of the TURNCredentialsManager
type TURNConfig struct {
	TimeBasedCredentials bool
	CredentialsTTL       util.Duration
	Secret               string
	Turns                []*Host
}

// Relay configuration type
type Relay struct {
	Addresses      []string
	CredentialsTTL util.Duration
	Secret         string
}

// HttpServerConfig is a config of the HTTP Management service server
type HttpServerConfig struct {
	LetsEncryptDomain string
	// CertFile is the location of the certificate
	CertFile string
	// CertKey is the location of the certificate private key
	CertKey string
	// AuthAudience identifies the recipients that the JWT is intended for (aud in JWT)
	AuthAudience string
	// AuthIssuer identifies principal that issued the JWT
	AuthIssuer string
	// AuthUserIDClaim is the name of the claim that used as user ID
	AuthUserIDClaim string
	// AuthKeysLocation is a location of JWT key set containing the public keys used to verify JWT
	AuthKeysLocation string
	// OIDCConfigEndpoint is the endpoint of an IDP manager to get OIDC configuration
	OIDCConfigEndpoint string
	// IdpSignKeyRefreshEnabled identifies the signing key is currently being rotated or not
	IdpSignKeyRefreshEnabled bool
	// Extra audience
	ExtraAuthAudience string
}

// Host represents a Netbird host (e.g. STUN, TURN, Signal)
type Host struct {
	Proto Protocol
	// URI e.g. turns://stun.netbird.io:4430 or signal.netbird.io:10000
	URI      string
	Username string
	Password string
}

// DeviceAuthorizationFlow represents Device Authorization Flow information
// that can be used by the client to login initiate a Oauth 2.0 device authorization grant flow
// see https://datatracker.ietf.org/doc/html/rfc8628
type DeviceAuthorizationFlow struct {
	Provider       string
	ProviderConfig ProviderConfig
}

// PKCEAuthorizationFlow represents Authorization Code Flow information
// that can be used by the client to login initiate a Oauth 2.0 authorization code grant flow
// with Proof Key for Code Exchange (PKCE). See https://datatracker.ietf.org/doc/html/rfc7636
type PKCEAuthorizationFlow struct {
	ProviderConfig ProviderConfig
}

// ProviderConfig has all attributes needed to initiate a device/pkce authorization flow
type ProviderConfig struct {
	// ClientID An IDP application client id
	ClientID string
	// ClientSecret An IDP application client secret
	ClientSecret string
	// Domain An IDP API domain
	// Deprecated. Use TokenEndpoint and DeviceAuthEndpoint
	Domain string
	// Audience An Audience for to authorization validation
	Audience string
	// TokenEndpoint is the endpoint of an IDP manager where clients can obtain access token
	TokenEndpoint string
	// DeviceAuthEndpoint is the endpoint of an IDP manager where clients can obtain device authorization code
	DeviceAuthEndpoint string
	// AuthorizationEndpoint is the endpoint of an IDP manager where clients can obtain authorization code
	AuthorizationEndpoint string
	// Scopes provides the scopes to be included in the token request
	Scope string
	// UseIDToken indicates if the id token should be used for authentication
	UseIDToken bool
	// RedirectURL handles authorization code from IDP manager
	RedirectURLs []string
	// DisablePromptLogin makes the PKCE flow to not prompt the user for login
	DisablePromptLogin bool
	// LoginFlag is used to configure the PKCE flow login behavior
	LoginFlag common.LoginFlag
}

// StoreConfig contains Store configuration
type StoreConfig struct {
	Engine types.Engine
}

// ReverseProxy contains reverse proxy configuration in front of management.
type ReverseProxy struct {
	// TrustedHTTPProxies represents a list of trusted HTTP proxies by their IP prefixes.
	// When extracting the real IP address from request headers, the middleware will verify
	// if the peer's address falls within one of these trusted IP prefixes.
	TrustedHTTPProxies []netip.Prefix

	// TrustedHTTPProxiesCount specifies the count of trusted HTTP proxies between the internet
	// and the server. When using the trusted proxy count method to extract the real IP address,
	// the middleware will search the X-Forwarded-For IP list from the rightmost by this count
	// minus one.
	TrustedHTTPProxiesCount uint

	// TrustedPeers represents a list of trusted peers by their IP prefixes.
	// These peers are considered trustworthy by the gRPC server operator,
	// and the middleware will attempt to extract the real IP address from
	// request headers if the peer's address falls within one of these
	// trusted IP prefixes.
	TrustedPeers []netip.Prefix
}
