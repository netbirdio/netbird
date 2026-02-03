package cmd

import (
	"context"
	"fmt"
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

// CombinedConfig is the root configuration for the combined server
type CombinedConfig struct {
	Server     ServerConfig     `yaml:"server"`
	Relay      RelayConfig      `yaml:"relay"`
	Signal     SignalConfig     `yaml:"signal"`
	Management ManagementConfig `yaml:"management"`
}

// ServerConfig contains server-wide settings
type ServerConfig struct {
	ListenAddress      string    `yaml:"listenAddress"`
	MetricsPort        int       `yaml:"metricsPort"`
	HealthcheckAddress string    `yaml:"healthcheckAddress"`
	LogLevel           string    `yaml:"logLevel"`
	LogFile            string    `yaml:"logFile"`
	TLS                TLSConfig `yaml:"tls"`
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
	Enabled bool `yaml:"enabled"`
	// Signal shares the server.listenAddress port
	// Reserved for future signal-specific settings
}

// ManagementConfig contains management service settings
type ManagementConfig struct {
	Enabled                  bool               `yaml:"enabled"`
	DataDir                  string             `yaml:"dataDir"`
	DnsDomain                string             `yaml:"dnsDomain"`
	SingleAccountModeDomain  string             `yaml:"singleAccountModeDomain"`
	DisableSingleAccountMode bool               `yaml:"disableSingleAccountMode"`
	DisableAnonymousMetrics  bool               `yaml:"disableAnonymousMetrics"`
	DisableGeoliteUpdate     bool               `yaml:"disableGeoliteUpdate"`
	UserDeleteFromIDPEnabled bool               `yaml:"userDeleteFromIDPEnabled"`
	DisableDefaultPolicy     bool               `yaml:"disableDefaultPolicy"`
	Auth                     AuthConfig         `yaml:"auth"`
	Stuns                    []HostConfig       `yaml:"stuns"`
	Relays                   RelaysConfig       `yaml:"relays"`
	SignalURI                string             `yaml:"signalUri"`
	Store                    StoreConfig        `yaml:"store"`
	ReverseProxy             ReverseProxyConfig `yaml:"reverseProxy"`
}

// AuthConfig contains authentication/identity provider settings
type AuthConfig struct {
	Enabled               bool              `yaml:"enabled"`
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
		},
		Relay: RelayConfig{
			Stun: StunConfig{
				Enabled:  false,
				Ports:    []int{3478},
				LogLevel: "info",
			},
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

	return cfg, nil
}

// Validate validates the configuration
func (c *CombinedConfig) Validate() error {
	// Check that at least one component is enabled
	if !c.Relay.Enabled && !c.Signal.Enabled && !c.Management.Enabled {
		return fmt.Errorf("at least one component (relay, signal, or management) must be enabled")
	}

	// Validate relay config only if enabled
	if c.Relay.Enabled {
		if c.Relay.ExposedAddress == "" {
			return fmt.Errorf("relay.exposedAddress is required when relay is enabled")
		}
		if c.Relay.AuthSecret == "" {
			return fmt.Errorf("relay.authSecret is required when relay is enabled")
		}

		if c.Relay.Stun.Enabled {
			if len(c.Relay.Stun.Ports) == 0 {
				return fmt.Errorf("relay.stun.ports is required when relay.stun.enabled is true")
			}
			seen := make(map[int]bool)
			for _, port := range c.Relay.Stun.Ports {
				if port <= 0 || port > 65535 {
					return fmt.Errorf("invalid STUN port %d: must be between 1 and 65535", port)
				}
				if seen[port] {
					return fmt.Errorf("duplicate STUN port %d", port)
				}
				seen[port] = true
			}
		}
	}

	// Validate management config only if enabled
	if c.Management.Enabled {
		if c.Management.DataDir == "" {
			return fmt.Errorf("management.dataDir is required when management is enabled")
		}
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

// ToManagementConfig converts CombinedConfig to management server config
func (c *CombinedConfig) ToManagementConfig() *nbconfig.Config {
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
		ttl, _ := time.ParseDuration(mgmt.Relays.CredentialsTTL)
		relayConfig = &nbconfig.Relay{
			Addresses:      mgmt.Relays.Addresses,
			CredentialsTTL: util.Duration{Duration: ttl},
			Secret:         mgmt.Relays.Secret,
		}
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

	// Build embedded IDP config
	var embeddedIdP *idp.EmbeddedIdPConfig
	if mgmt.Auth.Enabled {
		storageFile := mgmt.Auth.Storage.File
		if storageFile == "" {
			storageFile = path.Join(mgmt.DataDir, "idp.db")
		}

		embeddedIdP = &idp.EmbeddedIdPConfig{
			Enabled:               true,
			Issuer:                mgmt.Auth.Issuer,
			LocalAuthDisabled:     mgmt.Auth.LocalAuthDisabled,
			SignKeyRefreshEnabled: mgmt.Auth.SignKeyRefreshEnabled,
			Storage: idp.EmbeddedStorageConfig{
				Type: mgmt.Auth.Storage.Type,
				Config: idp.EmbeddedStorageTypeConfig{
					File: storageFile,
				},
			},
			DashboardRedirectURIs: mgmt.Auth.DashboardRedirectURIs,
			CLIRedirectURIs:       mgmt.Auth.CLIRedirectURIs,
		}

		if mgmt.Auth.Owner != nil && mgmt.Auth.Owner.Email != "" {
			embeddedIdP.Owner = &idp.OwnerConfig{
				Email: mgmt.Auth.Owner.Email,
				Hash:  mgmt.Auth.Owner.Password, // Will be hashed if plain text
			}
		}

		// Set HTTP config fields for embedded IDP
		httpConfig.AuthIssuer = mgmt.Auth.Issuer
		httpConfig.IdpSignKeyRefreshEnabled = mgmt.Auth.SignKeyRefreshEnabled
	}

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
	}
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
	log.WithContext(ctx).Warnf("DataStoreEncryptionKey generated. Add it to your config file to persist: encryptionKey: %q", key)

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
