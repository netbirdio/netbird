package config

import (
	"net/netip"

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
	EmbeddedIdP *idp.EmbeddedIdPConfig
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

// TURNConfig is a config of the TURNCredentialsManager
type TURNConfig struct {
	TimeBasedCredentials bool
	CredentialsTTL       util.Duration
	Secret               string
	Turns                []*Host
}

// Relay configuration type
//
// Addresses is the legacy flat list and is forwarded to clients as
// RelayConfig.urls for back-compat with older agents.
//
// Endpoints, when populated, additionally announces the transports each
// relay URL supports. Under GeoDNS, where one URL resolves to several
// physical relays in different regions, Transports must be the
// intersection of the transports supported by every backend behind that
// hostname — clients pick a transport per URL and the management server
// does not probe individual backends. If a single backend in the pool
// does not support h3/WebTransport, drop "wt" from Transports so no
// client tries it against that hostname.
type Relay struct {
	Addresses      []string
	Endpoints      []RelayEndpoint
	CredentialsTTL util.Duration
	Secret         string
}

// RelayEndpoint pairs a relay URL with the transports it advertises.
// Transports values: "ws", "quic", "wt". Empty Transports means "unknown,
// let the client try whatever it supports".
type RelayEndpoint struct {
	URL        string
	Transports []string
}

// KnownRelayTransports is the set of transport identifiers the management
// server accepts in RelayEndpoint.Transports. Anything outside this set is
// silently dropped at config load — we don't want a typo in Transports to
// turn into clients trying a dialer that doesn't exist.
var KnownRelayTransports = map[string]struct{}{
	"ws":   {},
	"quic": {},
	"wt":   {},
}

// HasURLs reports whether any relay address is configured (either via the
// legacy Addresses slice or via Endpoints). Callers that only care
// "is the relay feature on for this server" should use this rather than
// checking either field directly.
func (r *Relay) HasURLs() bool {
	if r == nil {
		return false
	}
	if len(r.Addresses) > 0 {
		return true
	}
	for _, ep := range r.Endpoints {
		if ep.URL != "" {
			return true
		}
	}
	return false
}

// AllURLs returns every relay URL the management server will advertise,
// preserving order with Endpoints listed first and any Addresses not also
// covered by an Endpoint appended after. Used for logging and for callers
// that want a flat URL list without caring about transport hints.
func (r *Relay) AllURLs() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.Endpoints)+len(r.Addresses))
	out := make([]string, 0, len(r.Endpoints)+len(r.Addresses))
	for _, ep := range r.Endpoints {
		if ep.URL == "" {
			continue
		}
		if _, ok := seen[ep.URL]; ok {
			continue
		}
		seen[ep.URL] = struct{}{}
		out = append(out, ep.URL)
	}
	for _, addr := range r.Addresses {
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// Normalize trims unknown transport identifiers from each Endpoint, dropping
// dupes and empty URLs. Returns the unknown transports it discarded so the
// caller can surface them as a warning at startup.
//
// Does not error on empty Transports — an empty list is a valid "unknown,
// try everything" signal, distinct from "I tried to declare it but typoed".
func (r *Relay) Normalize() (unknownTransports []string) {
	if r == nil {
		return nil
	}
	if len(r.Endpoints) == 0 {
		return nil
	}
	dropped := map[string]struct{}{}
	urlSeen := make(map[string]struct{}, len(r.Endpoints))
	cleaned := make([]RelayEndpoint, 0, len(r.Endpoints))
	for _, ep := range r.Endpoints {
		if ep.URL == "" {
			continue
		}
		if _, dup := urlSeen[ep.URL]; dup {
			continue
		}
		urlSeen[ep.URL] = struct{}{}

		filtered := make([]string, 0, len(ep.Transports))
		tSeen := make(map[string]struct{}, len(ep.Transports))
		for _, t := range ep.Transports {
			if _, ok := KnownRelayTransports[t]; !ok {
				dropped[t] = struct{}{}
				continue
			}
			if _, ok := tSeen[t]; ok {
				continue
			}
			tSeen[t] = struct{}{}
			filtered = append(filtered, t)
		}
		cleaned = append(cleaned, RelayEndpoint{URL: ep.URL, Transports: filtered})
	}
	r.Endpoints = cleaned

	if len(dropped) == 0 {
		return nil
	}
	out := make([]string, 0, len(dropped))
	for t := range dropped {
		out = append(out, t)
	}
	return out
}

// HttpServerConfig is a config of the HTTP Management service server
type HttpServerConfig struct {
	LetsEncryptDomain string
	// CertFile is the location of the certificate
	CertFile string
	// CertKey is the location of the certificate private key
	CertKey string
	// AuthClientID is the client id used for proxy SSO auth
	AuthClientID string
	// AuthAudience identifies the recipients that the JWT is intended for (aud in JWT)
	AuthAudience string
	// CLIAuthAudience identifies the client app recipients that the JWT is intended for (aud in JWT)
	// Used only in conjunction with EmbeddedIdP
	CLIAuthAudience string
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
	// AuthCallbackDomain contains the callback domain
	AuthCallbackURL string
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

	// AccessLogRetentionDays specifies the number of days to retain access logs.
	// Logs older than this duration will be automatically deleted during cleanup.
	// A value of 0 will default to 7 days. Negative means logs are kept indefinitely (no cleanup).
	AccessLogRetentionDays int

	// AccessLogCleanupIntervalHours specifies how often (in hours) to run the cleanup routine.
	// Defaults to 24 hours if not set or set to 0.
	AccessLogCleanupIntervalHours int
}
