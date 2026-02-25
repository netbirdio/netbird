package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

// CombinedConfig is the root configuration for the combined server.
// The combined server is primarily a Management server with optional embedded
// Signal, Relay, and STUN services.
//
// Architecture:
//   - Management: Always runs locally (this IS the management server)
//   - Signal: Runs locally by default; disabled if server.signalUri is set
//   - Relay: Runs locally by default; disabled if server.relays is set
//   - STUN: Runs locally on port 3478 by default; disabled if server.stuns is set
//
// All user-facing settings are under "server". The relay/signal/management
// fields are internal and populated automatically from server settings.
type CombinedConfig struct {
	Server ServerConfig `yaml:"server"`

	// Internal configs - populated from Server settings, not user-configurable
	Relay      RelayConfig      `yaml:"-"`
	Signal     SignalConfig     `yaml:"-"`
	Management ManagementConfig `yaml:"-"`
}

// ServerConfig contains server-wide settings
// In simplified mode, this contains all configuration
type ServerConfig struct {
	ListenAddress      string    `yaml:"listenAddress"`
	MetricsPort        int       `yaml:"metricsPort"`
	HealthcheckAddress string    `yaml:"healthcheckAddress"`
	LogLevel           string    `yaml:"logLevel"`
	LogFile            string    `yaml:"logFile"`
	TLS                TLSConfig `yaml:"tls"`

	// Simplified config fields (used when relay/signal/management sections are omitted)
	ExposedAddress string `yaml:"exposedAddress"` // Public address with protocol (e.g., "https://example.com:443")
	StunPorts      []int  `yaml:"stunPorts"`      // STUN ports (empty to disable local STUN)
	AuthSecret     string `yaml:"authSecret"`     // Shared secret for relay authentication
	DataDir        string `yaml:"dataDir"`        // Data directory for all services

	// External service overrides (simplified mode)
	// When these are set, the corresponding local service is NOT started
	// and these values are used for client configuration instead
	Stuns     []HostConfig `yaml:"stuns"`     // External STUN servers (disables local STUN)
	Relays    RelaysConfig `yaml:"relays"`    // External relay servers (disables local relay)
	SignalURI string       `yaml:"signalUri"` // External signal server (disables local signal)

	// Management settings (simplified mode)
	DisableAnonymousMetrics bool               `yaml:"disableAnonymousMetrics"`
	DisableGeoliteUpdate    bool               `yaml:"disableGeoliteUpdate"`
	Auth                    AuthConfig         `yaml:"auth"`
	Store                   StoreConfig        `yaml:"store"`
	ActivityStore           StoreConfig        `yaml:"activityStore"`
	AuthStore               StoreConfig        `yaml:"authStore"`
	ReverseProxy            ReverseProxyConfig `yaml:"reverseProxy"`
}

// TLSConfig contains TLS/HTTPS settings
type TLSConfig struct {
	CertFile    string            `yaml:"certFile"`
	KeyFile     string            `yaml:"keyFile"`
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`
}

// LetsEncryptConfig contains Let's Encrypt settings
type LetsEncryptConfig struct {
	Enabled    bool     `yaml:"enabled"`
	DataDir    string   `yaml:"dataDir"`
	Domains    []string `yaml:"domains"`
	Email      string   `yaml:"email"`
	AWSRoute53 bool     `yaml:"awsRoute53"`
}

// RelayConfig contains relay service settings
type RelayConfig struct {
	Enabled        bool       `yaml:"enabled"`
	ExposedAddress string     `yaml:"exposedAddress"`
	AuthSecret     string     `yaml:"authSecret"`
	LogLevel       string     `yaml:"logLevel"`
	Stun           StunConfig `yaml:"stun"`
}

// StunConfig contains embedded STUN service settings
type StunConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Ports    []int  `yaml:"ports"`
	LogLevel string `yaml:"logLevel"`
}

// SignalConfig contains signal service settings
type SignalConfig struct {
	Enabled  bool   `yaml:"enabled"`
	LogLevel string `yaml:"logLevel"`
}

// ManagementConfig contains management service settings
type ManagementConfig struct {
	Enabled                 bool               `yaml:"enabled"`
	LogLevel                string             `yaml:"logLevel"`
	DataDir                 string             `yaml:"dataDir"`
	DnsDomain               string             `yaml:"dnsDomain"`
	DisableAnonymousMetrics bool               `yaml:"disableAnonymousMetrics"`
	DisableGeoliteUpdate    bool               `yaml:"disableGeoliteUpdate"`
	DisableDefaultPolicy    bool               `yaml:"disableDefaultPolicy"`
	Auth                    AuthConfig         `yaml:"auth"`
	Stuns                   []HostConfig       `yaml:"stuns"`
	Relays                  RelaysConfig       `yaml:"relays"`
	SignalURI               string             `yaml:"signalUri"`
	Store                   StoreConfig        `yaml:"store"`
	ReverseProxy            ReverseProxyConfig `yaml:"reverseProxy"`
}

// AuthConfig contains authentication/identity provider settings
type AuthConfig struct {
	Issuer                string            `yaml:"issuer"`
	LocalAuthDisabled     bool              `yaml:"localAuthDisabled"`
	SignKeyRefreshEnabled bool              `yaml:"signKeyRefreshEnabled"`
	Storage               AuthStorageConfig `yaml:"storage"`
	DashboardRedirectURIs []string          `yaml:"dashboardRedirectURIs"`
	CLIRedirectURIs       []string          `yaml:"cliRedirectURIs"`
	Owner                 *AuthOwnerConfig  `yaml:"owner,omitempty"`
}

// AuthStorageConfig contains auth storage settings
type AuthStorageConfig struct {
	Type string `yaml:"type"`
	File string `yaml:"file"`
}

// AuthOwnerConfig contains initial admin user settings
type AuthOwnerConfig struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
}

// HostConfig represents a STUN/TURN/Signal host
type HostConfig struct {
	URI      string `yaml:"uri"`
	Proto    string `yaml:"proto,omitempty"` // udp, dtls, tcp, http, https - defaults based on URI scheme
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// RelaysConfig contains external relay server settings for clients
type RelaysConfig struct {
	Addresses      []string `yaml:"addresses"`
	CredentialsTTL string   `yaml:"credentialsTTL"`
	Secret         string   `yaml:"secret"`
}

// StoreConfig contains database settings
type StoreConfig struct {
	Engine        string `yaml:"engine"`
	EncryptionKey string `yaml:"encryptionKey"`
	DSN           string `yaml:"dsn"` // Connection string for postgres or mysql engines
}

// ReverseProxyConfig contains reverse proxy settings
type ReverseProxyConfig struct {
	TrustedHTTPProxies      []string `yaml:"trustedHTTPProxies"`
	TrustedHTTPProxiesCount uint     `yaml:"trustedHTTPProxiesCount"`
	TrustedPeers            []string `yaml:"trustedPeers"`
}

// DefaultConfig returns a CombinedConfig with default values
func DefaultConfig() *CombinedConfig {
	return &CombinedConfig{
		Server: ServerConfig{
			ListenAddress:      ":443",
			MetricsPort:        9090,
			HealthcheckAddress: ":9000",
			LogLevel:           "info",
			LogFile:            "console",
			StunPorts:          []int{3478},
			DataDir:            "/var/lib/netbird/",
			Auth: AuthConfig{
				Storage: AuthStorageConfig{
					Type: "sqlite3",
				},
			},
			Store: StoreConfig{
				Engine: "sqlite",
			},
		},
		Relay: RelayConfig{
			// LogLevel inherited from Server.LogLevel via ApplySimplifiedDefaults
			Stun: StunConfig{
				Enabled: false,
				Ports:   []int{3478},
				// LogLevel inherited from Server.LogLevel via ApplySimplifiedDefaults
			},
		},
		Signal: SignalConfig{
			// LogLevel inherited from Server.LogLevel via ApplySimplifiedDefaults
		},
		Management: ManagementConfig{
			DataDir: "/var/lib/netbird/",
			Auth: AuthConfig{
				Storage: AuthStorageConfig{
					Type: "sqlite3",
				},
			},
			Relays: RelaysConfig{
				CredentialsTTL: "12h",
			},
			Store: StoreConfig{
				Engine: "sqlite",
			},
		},
	}
}

// hasRequiredSettings returns true if the configuration has the required server settings
func (c *CombinedConfig) hasRequiredSettings() bool {
	return c.Server.ExposedAddress != ""
}

// parseExposedAddress extracts protocol, host, and host:port from the exposed address
// Input format: "https://example.com:443" or "http://example.com:8080" or "example.com:443"
// Returns: protocol ("https" or "http"), hostname only, and host:port
func parseExposedAddress(exposedAddress string) (protocol, hostname, hostPort string) {
	// Default to https if no protocol specified
	protocol = "https"
	hostPort = exposedAddress

	// Check for protocol prefix
	if strings.HasPrefix(exposedAddress, "https://") {
		protocol = "https"
		hostPort = strings.TrimPrefix(exposedAddress, "https://")
	} else if strings.HasPrefix(exposedAddress, "http://") {
		protocol = "http"
		hostPort = strings.TrimPrefix(exposedAddress, "http://")
	}

	// Extract hostname (without port)
	hostname = hostPort
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		hostname = host
	}

	return protocol, hostname, hostPort
}

// ApplySimplifiedDefaults populates internal relay/signal/management configs from server settings.
// Management is always enabled. Signal, Relay, and STUN are enabled unless external
// overrides are configured (server.signalUri, server.relays, server.stuns).
func (c *CombinedConfig) ApplySimplifiedDefaults() {
	if !c.hasRequiredSettings() {
		return
	}

	// Parse exposed address to extract protocol and hostname
	exposedProto, exposedHost, exposedHostPort := parseExposedAddress(c.Server.ExposedAddress)

	// Check for external service overrides
	hasExternalRelay := len(c.Server.Relays.Addresses) > 0
	hasExternalSignal := c.Server.SignalURI != ""
	hasExternalStuns := len(c.Server.Stuns) > 0

	// Default stunPorts to [3478] if not specified and no external STUN
	if len(c.Server.StunPorts) == 0 && !hasExternalStuns {
		c.Server.StunPorts = []int{3478}
	}

	c.applyRelayDefaults(exposedProto, exposedHostPort, hasExternalRelay, hasExternalStuns)
	c.applySignalDefaults(hasExternalSignal)
	c.applyManagementDefaults(exposedHost)

	// Auto-configure client settings (stuns, relays, signalUri)
	c.autoConfigureClientSettings(exposedProto, exposedHost, exposedHostPort, hasExternalStuns, hasExternalRelay, hasExternalSignal)
}

// applyRelayDefaults configures the relay service if no external relay is configured.
func (c *CombinedConfig) applyRelayDefaults(exposedProto, exposedHostPort string, hasExternalRelay, hasExternalStuns bool) {
	if hasExternalRelay {
		return
	}

	c.Relay.Enabled = true
	relayProto := "rel"
	if exposedProto == "https" {
		relayProto = "rels"
	}
	c.Relay.ExposedAddress = fmt.Sprintf("%s://%s", relayProto, exposedHostPort)
	c.Relay.AuthSecret = c.Server.AuthSecret
	if c.Relay.LogLevel == "" {
		c.Relay.LogLevel = c.Server.LogLevel
	}

	// Enable local STUN only if no external STUN servers and stunPorts are configured
	if !hasExternalStuns && len(c.Server.StunPorts) > 0 {
		c.Relay.Stun.Enabled = true
		c.Relay.Stun.Ports = c.Server.StunPorts
		if c.Relay.Stun.LogLevel == "" {
			c.Relay.Stun.LogLevel = c.Server.LogLevel
		}
	}
}

// applySignalDefaults configures the signal service if no external signal is configured.
func (c *CombinedConfig) applySignalDefaults(hasExternalSignal bool) {
	if hasExternalSignal {
		return
	}

	c.Signal.Enabled = true
	if c.Signal.LogLevel == "" {
		c.Signal.LogLevel = c.Server.LogLevel
	}
}

// applyManagementDefaults configures the management service (always enabled).
func (c *CombinedConfig) applyManagementDefaults(exposedHost string) {
	c.Management.Enabled = true
	if c.Management.LogLevel == "" {
		c.Management.LogLevel = c.Server.LogLevel
	}
	if c.Management.DataDir == "" || c.Management.DataDir == "/var/lib/netbird/" {
		c.Management.DataDir = c.Server.DataDir
	}
	c.Management.DnsDomain = exposedHost
	c.Management.DisableAnonymousMetrics = c.Server.DisableAnonymousMetrics
	c.Management.DisableGeoliteUpdate = c.Server.DisableGeoliteUpdate
	// Copy auth config from server if management auth issuer is not set
	if c.Management.Auth.Issuer == "" && c.Server.Auth.Issuer != "" {
		c.Management.Auth = c.Server.Auth
	}

	// Copy store config from server if not set
	if c.Management.Store.Engine == "" || c.Management.Store.Engine == "sqlite" {
		if c.Server.Store.Engine != "" {
			c.Management.Store = c.Server.Store
		}
	}

	// Copy reverse proxy config from server
	if len(c.Server.ReverseProxy.TrustedHTTPProxies) > 0 || c.Server.ReverseProxy.TrustedHTTPProxiesCount > 0 || len(c.Server.ReverseProxy.TrustedPeers) > 0 {
		c.Management.ReverseProxy = c.Server.ReverseProxy
	}
}

// autoConfigureClientSettings sets up STUN/relay/signal URIs for clients
// External overrides from server config take precedence over auto-generated values
func (c *CombinedConfig) autoConfigureClientSettings(exposedProto, exposedHost, exposedHostPort string, hasExternalStuns, hasExternalRelay, hasExternalSignal bool) {
	// Determine relay protocol from exposed protocol
	relayProto := "rel"
	if exposedProto == "https" {
		relayProto = "rels"
	}

	// Configure STUN servers for clients
	if hasExternalStuns {
		// Use external STUN servers from server config
		c.Management.Stuns = c.Server.Stuns
	} else if len(c.Server.StunPorts) > 0 && len(c.Management.Stuns) == 0 {
		// Auto-configure local STUN servers for all ports
		for _, port := range c.Server.StunPorts {
			c.Management.Stuns = append(c.Management.Stuns, HostConfig{
				URI: fmt.Sprintf("stun:%s:%d", exposedHost, port),
			})
		}
	}

	// Configure relay for clients
	if hasExternalRelay {
		// Use external relay config from server
		c.Management.Relays = c.Server.Relays
	} else if len(c.Management.Relays.Addresses) == 0 {
		// Auto-configure local relay
		c.Management.Relays.Addresses = []string{
			fmt.Sprintf("%s://%s", relayProto, exposedHostPort),
		}
	}
	if c.Management.Relays.Secret == "" {
		c.Management.Relays.Secret = c.Server.AuthSecret
	}
	if c.Management.Relays.CredentialsTTL == "" {
		c.Management.Relays.CredentialsTTL = "12h"
	}

	// Configure signal for clients
	if hasExternalSignal {
		// Use external signal URI from server config
		c.Management.SignalURI = c.Server.SignalURI
	} else if c.Management.SignalURI == "" {
		// Auto-configure local signal
		c.Management.SignalURI = fmt.Sprintf("%s://%s", exposedProto, exposedHostPort)
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(configPath string) (*CombinedConfig, error) {
	cfg := DefaultConfig()

	if configPath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Populate internal configs from server settings
	cfg.ApplySimplifiedDefaults()

	return cfg, nil
}

// Validate validates the configuration
func (c *CombinedConfig) Validate() error {
	if c.Server.ExposedAddress == "" {
		return fmt.Errorf("server.exposedAddress is required")
	}
	if c.Server.DataDir == "" {
		return fmt.Errorf("server.dataDir is required")
	}

	// Validate STUN ports
	seen := make(map[int]bool)
	for _, port := range c.Server.StunPorts {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("invalid server.stunPorts value %d: must be between 1 and 65535", port)
		}
		if seen[port] {
			return fmt.Errorf("duplicate STUN port %d in server.stunPorts", port)
		}
		seen[port] = true
	}

	// authSecret is required only if running local relay (no external relay configured)
	hasExternalRelay := len(c.Server.Relays.Addresses) > 0
	if !hasExternalRelay && c.Server.AuthSecret == "" {
		return fmt.Errorf("server.authSecret is required when running local relay")
	}

	return nil
}

// HasTLSCert returns true if TLS certificate files are configured
func (c *CombinedConfig) HasTLSCert() bool {
	return c.Server.TLS.CertFile != "" && c.Server.TLS.KeyFile != ""
}

// HasLetsEncrypt returns true if Let's Encrypt is configured
func (c *CombinedConfig) HasLetsEncrypt() bool {
	return c.Server.TLS.LetsEncrypt.Enabled &&
		c.Server.TLS.LetsEncrypt.DataDir != "" &&
		len(c.Server.TLS.LetsEncrypt.Domains) > 0
}

// parseExplicitProtocol parses an explicit protocol string to nbconfig.Protocol
func parseExplicitProtocol(proto string) (nbconfig.Protocol, bool) {
	switch strings.ToLower(proto) {
	case "udp":
		return nbconfig.UDP, true
	case "dtls":
		return nbconfig.DTLS, true
	case "tcp":
		return nbconfig.TCP, true
	case "http":
		return nbconfig.HTTP, true
	case "https":
		return nbconfig.HTTPS, true
	default:
		return "", false
	}
}

// parseStunProtocol determines protocol for STUN/TURN servers.
// stun: → UDP, stuns: → DTLS, turn: → UDP, turns: → DTLS
// Explicit proto overrides URI scheme. Defaults to UDP.
func parseStunProtocol(uri, proto string) nbconfig.Protocol {
	if proto != "" {
		if p, ok := parseExplicitProtocol(proto); ok {
			return p
		}
	}

	uri = strings.ToLower(uri)
	switch {
	case strings.HasPrefix(uri, "stuns:"):
		return nbconfig.DTLS
	case strings.HasPrefix(uri, "turns:"):
		return nbconfig.DTLS
	default:
		// stun:, turn:, or no scheme - default to UDP
		return nbconfig.UDP
	}
}

// parseSignalProtocol determines protocol for Signal servers.
// https:// → HTTPS, http:// → HTTP. Defaults to HTTPS.
func parseSignalProtocol(uri string) nbconfig.Protocol {
	uri = strings.ToLower(uri)
	switch {
	case strings.HasPrefix(uri, "http://"):
		return nbconfig.HTTP
	default:
		// https:// or no scheme - default to HTTPS
		return nbconfig.HTTPS
	}
}

// stripSignalProtocol removes the protocol prefix from a signal URI.
// Returns just the host:port (e.g., "selfhosted2.demo.netbird.io:443").
func stripSignalProtocol(uri string) string {
	uri = strings.TrimPrefix(uri, "https://")
	uri = strings.TrimPrefix(uri, "http://")
	return uri
}

func buildRelayConfig(relays RelaysConfig) (*nbconfig.Relay, error) {
	var ttl time.Duration
	if relays.CredentialsTTL != "" {
		var err error
		ttl, err = time.ParseDuration(relays.CredentialsTTL)
		if err != nil {
			return nil, fmt.Errorf("invalid relay credentials TTL %q: %w", relays.CredentialsTTL, err)
		}
	}
	return &nbconfig.Relay{
		Addresses:      relays.Addresses,
		CredentialsTTL: util.Duration{Duration: ttl},
		Secret:         relays.Secret,
	}, nil
}

// buildEmbeddedIdPConfig builds the embedded IdP configuration.
// authStore overrides auth.storage when set.
func (c *CombinedConfig) buildEmbeddedIdPConfig(mgmt ManagementConfig) (*idp.EmbeddedIdPConfig, error) {
	authStorageType := mgmt.Auth.Storage.Type
	authStorageDSN := c.Server.AuthStore.DSN
	if c.Server.AuthStore.Engine != "" {
		authStorageType = c.Server.AuthStore.Engine
	}
	if authStorageType == "" {
		authStorageType = "sqlite3"
	}
	authStorageFile := ""
	if authStorageType == "postgres" {
		if authStorageDSN == "" {
			return nil, fmt.Errorf("authStore.dsn is required when authStore.engine is postgres")
		}
	} else {
		authStorageFile = path.Join(mgmt.DataDir, "idp.db")
	}

	cfg := &idp.EmbeddedIdPConfig{
		Enabled:               true,
		Issuer:                mgmt.Auth.Issuer,
		LocalAuthDisabled:     mgmt.Auth.LocalAuthDisabled,
		SignKeyRefreshEnabled: mgmt.Auth.SignKeyRefreshEnabled,
		Storage: idp.EmbeddedStorageConfig{
			Type: authStorageType,
			Config: idp.EmbeddedStorageTypeConfig{
				File: authStorageFile,
				DSN:  authStorageDSN,
			},
		},
		DashboardRedirectURIs: mgmt.Auth.DashboardRedirectURIs,
		CLIRedirectURIs:       mgmt.Auth.CLIRedirectURIs,
	}

	if mgmt.Auth.Owner != nil && mgmt.Auth.Owner.Email != "" {
		cfg.Owner = &idp.OwnerConfig{
			Email: mgmt.Auth.Owner.Email,
			Hash:  mgmt.Auth.Owner.Password,
		}
	}

	return cfg, nil
}

// ToManagementConfig converts CombinedConfig to management server config
func (c *CombinedConfig) ToManagementConfig() (*nbconfig.Config, error) {
	mgmt := c.Management

	// Build STUN hosts
	var stuns []*nbconfig.Host
	for _, s := range mgmt.Stuns {
		stuns = append(stuns, &nbconfig.Host{
			URI:      s.URI,
			Proto:    parseStunProtocol(s.URI, s.Proto),
			Username: s.Username,
			Password: s.Password,
		})
	}

	// Build relay config
	var relayConfig *nbconfig.Relay
	if len(mgmt.Relays.Addresses) > 0 || mgmt.Relays.Secret != "" {
		relay, err := buildRelayConfig(mgmt.Relays)
		if err != nil {
			return nil, err
		}
		relayConfig = relay
	}

	// Build signal config
	var signalConfig *nbconfig.Host
	if mgmt.SignalURI != "" {
		signalConfig = &nbconfig.Host{
			URI:   stripSignalProtocol(mgmt.SignalURI),
			Proto: parseSignalProtocol(mgmt.SignalURI),
		}
	}

	// Build store config
	storeConfig := nbconfig.StoreConfig{
		Engine: types.Engine(mgmt.Store.Engine),
	}

	// Build reverse proxy config
	reverseProxy := nbconfig.ReverseProxy{
		TrustedHTTPProxiesCount: mgmt.ReverseProxy.TrustedHTTPProxiesCount,
	}
	for _, p := range mgmt.ReverseProxy.TrustedHTTPProxies {
		if prefix, err := netip.ParsePrefix(p); err == nil {
			reverseProxy.TrustedHTTPProxies = append(reverseProxy.TrustedHTTPProxies, prefix)
		}
	}
	for _, p := range mgmt.ReverseProxy.TrustedPeers {
		if prefix, err := netip.ParsePrefix(p); err == nil {
			reverseProxy.TrustedPeers = append(reverseProxy.TrustedPeers, prefix)
		}
	}

	// Build HTTP config (required, even if empty)
	httpConfig := &nbconfig.HttpServerConfig{}

	// Build embedded IDP config (always enabled in combined server)
	embeddedIdP, err := c.buildEmbeddedIdPConfig(mgmt)
	if err != nil {
		return nil, err
	}

	// Set HTTP config fields for embedded IDP
	httpConfig.AuthIssuer = mgmt.Auth.Issuer
	httpConfig.AuthAudience = "netbird-dashboard"
	httpConfig.AuthClientID = httpConfig.AuthAudience
	httpConfig.CLIAuthAudience = "netbird-cli"
	httpConfig.AuthUserIDClaim = "sub"
	httpConfig.AuthKeysLocation = mgmt.Auth.Issuer + "/keys"
	httpConfig.OIDCConfigEndpoint = mgmt.Auth.Issuer + "/.well-known/openid-configuration"
	httpConfig.IdpSignKeyRefreshEnabled = mgmt.Auth.SignKeyRefreshEnabled
	callbackURL := strings.TrimSuffix(httpConfig.AuthIssuer, "/oauth2")
	httpConfig.AuthCallbackURL = callbackURL + types.ProxyCallbackEndpointFull

	return &nbconfig.Config{
		Stuns:                  stuns,
		Relay:                  relayConfig,
		Signal:                 signalConfig,
		Datadir:                mgmt.DataDir,
		DataStoreEncryptionKey: mgmt.Store.EncryptionKey,
		HttpConfig:             httpConfig,
		StoreConfig:            storeConfig,
		ReverseProxy:           reverseProxy,
		DisableDefaultPolicy:   mgmt.DisableDefaultPolicy,
		EmbeddedIdP:            embeddedIdP,
	}, nil
}

// ApplyEmbeddedIdPConfig applies embedded IdP configuration to the management config.
// This mirrors the logic in management/cmd/management.go ApplyEmbeddedIdPConfig.
func ApplyEmbeddedIdPConfig(ctx context.Context, cfg *nbconfig.Config, mgmtPort int, disableSingleAccMode bool) error {
	if cfg.EmbeddedIdP == nil || !cfg.EmbeddedIdP.Enabled {
		return nil
	}

	// Embedded IdP requires single account mode
	if disableSingleAccMode {
		return fmt.Errorf("embedded IdP requires single account mode; multiple account mode is not supported with embedded IdP")
	}

	// Set LocalAddress for embedded IdP, used for internal JWT validation
	cfg.EmbeddedIdP.LocalAddress = fmt.Sprintf("localhost:%d", mgmtPort)

	// Set storage defaults based on Datadir
	if cfg.EmbeddedIdP.Storage.Type == "" {
		cfg.EmbeddedIdP.Storage.Type = "sqlite3"
	}
	if cfg.EmbeddedIdP.Storage.Config.File == "" && cfg.Datadir != "" {
		cfg.EmbeddedIdP.Storage.Config.File = path.Join(cfg.Datadir, "idp.db")
	}

	issuer := cfg.EmbeddedIdP.Issuer

	// Ensure HttpConfig exists
	if cfg.HttpConfig == nil {
		cfg.HttpConfig = &nbconfig.HttpServerConfig{}
	}

	// Set HttpConfig values from EmbeddedIdP
	cfg.HttpConfig.AuthIssuer = issuer
	cfg.HttpConfig.AuthAudience = "netbird-dashboard"
	cfg.HttpConfig.CLIAuthAudience = "netbird-cli"
	cfg.HttpConfig.AuthUserIDClaim = "sub"
	cfg.HttpConfig.AuthKeysLocation = issuer + "/keys"
	cfg.HttpConfig.OIDCConfigEndpoint = issuer + "/.well-known/openid-configuration"
	cfg.HttpConfig.IdpSignKeyRefreshEnabled = true

	return nil
}

// EnsureEncryptionKey generates an encryption key if not set.
// Unlike management server, we don't write back to the config file.
func EnsureEncryptionKey(ctx context.Context, cfg *nbconfig.Config) error {
	if cfg.DataStoreEncryptionKey != "" {
		return nil
	}

	log.WithContext(ctx).Infof("DataStoreEncryptionKey is not set, generating a new key")
	key, err := crypt.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate datastore encryption key: %v", err)
	}
	cfg.DataStoreEncryptionKey = key
	keyPreview := key[:8] + "..."
	log.WithContext(ctx).Warnf("DataStoreEncryptionKey generated (%s); add it to your config file under 'server.store.encryptionKey' to persist across restarts", keyPreview)

	return nil
}

// LogConfigInfo logs informational messages about the loaded configuration
func LogConfigInfo(cfg *nbconfig.Config) {
	if cfg.EmbeddedIdP != nil && cfg.EmbeddedIdP.Enabled {
		log.Infof("running with the embedded IdP: %v", cfg.EmbeddedIdP.Issuer)
	}
	if cfg.Relay != nil {
		log.Infof("Relay addresses: %v", cfg.Relay.Addresses)
	}
}
