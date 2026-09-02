package proxy

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/acme"
	"github.com/netbirdio/netbird/trustedproxy"
)

// Config bundles every knob the proxy reads at construction time. It mirrors
// the public fields on Server so library callers don't have to learn the
// internal struct layout. Zero values mean "feature off" or "fall back to the
// internal default" depending on the field — see the per-field doc.
//
// The standalone binary continues to populate Server fields directly, so
// adding fields here must not change the zero-value behaviour of Server.
type Config struct {
	// ListenAddr is the TCP address the main listener binds. Required.
	ListenAddr string `yaml:"listenAddress" env:"NB_PROXY_ADDRESS" flag:"addr"`
	// ID identifies this proxy instance to management. Empty values are
	// replaced with a timestamped default at Server.Start time (see
	// initDefaults), not in New.
	ID string `yaml:"id" env:"-"`
	// Logger is the logrus logger used everywhere. Empty values fall
	// back to log.StandardLogger() at Server.Start time (see
	// initDefaults), not in New.
	Logger *log.Logger `yaml:"-" env:"-" flag:"-"`
	// Version is the build version string reported to management. Empty
	// values are replaced with "dev" at Server.Start time (see
	// initDefaults), not in New.
	Version string `yaml:"-" env:"-" flag:"-"`
	// ProxyURL is the public address operators use to reach this proxy.
	ProxyURL string `yaml:"domain" env:"NB_PROXY_DOMAIN" flag:"domain"`
	// ManagementAddress is the gRPC URL of the management server.
	ManagementAddress string `yaml:"managementAddress" env:"NB_PROXY_MANAGEMENT_ADDRESS" flag:"mgmt"`
	// ProxyToken authenticates this proxy with the management server.
	ProxyToken string `yaml:"proxyToken" env:"NB_PROXY_TOKEN"`

	// CertificateDirectory is the directory holding TLS certificate
	// material (static or ACME-provisioned).
	CertificateDirectory string `yaml:"certificateDirectory" env:"NB_PROXY_CERTIFICATE_DIRECTORY" flag:"cert-dir"`
	// CertificateFile is the certificate filename within
	// CertificateDirectory.
	CertificateFile string `yaml:"certificateFile" env:"NB_PROXY_CERTIFICATE_FILE" flag:"cert-file"`
	// CertificateKeyFile is the private key filename within
	// CertificateDirectory.
	CertificateKeyFile string `yaml:"certificateKeyFile" env:"NB_PROXY_CERTIFICATE_KEY_FILE" flag:"cert-key-file"`
	// GenerateACMECertificates toggles ACME certificate provisioning.
	GenerateACMECertificates bool `yaml:"generateACMECertificates" env:"NB_PROXY_ACME_CERTIFICATES" flag:"acme-certs"`
	// ACMEChallengeAddress is the listen address for HTTP-01 challenges.
	ACMEChallengeAddress string `yaml:"acmeChallengeAddress" env:"NB_PROXY_ACME_ADDRESS" flag:"acme-addr"`
	// ACMEDirectory is the ACME directory URL (Let's Encrypt by default).
	ACMEDirectory string `yaml:"acmeDirectory" env:"NB_PROXY_ACME_DIRECTORY" flag:"acme-dir"`
	// ACMEEABKID is the External Account Binding Key ID for CAs that
	// require EAB (e.g. ZeroSSL).
	ACMEEABKID string `yaml:"acmeEABKID" env:"NB_PROXY_ACME_EAB_KID" flag:"acme-eab-kid"`
	// ACMEEABHMACKey is the External Account Binding HMAC key for CAs
	// that require EAB.
	ACMEEABHMACKey string `yaml:"acmeEABHMACKey" env:"NB_PROXY_ACME_EAB_HMAC_KEY" flag:"acme-eab-hmac-key"`
	// ACMEChallengeType is the ACME challenge type ("tls-alpn-01" or
	// "http-01"). Empty defaults to "tls-alpn-01".
	ACMEChallengeType string `yaml:"acmeChallengeType" env:"NB_PROXY_ACME_CHALLENGE_TYPE" flag:"acme-challenge-type"`
	// CertLockMethod controls how ACME certificate locks are coordinated
	// across replicas.
	CertLockMethod acme.CertLockMethod `yaml:"certLockMethod" env:"NB_PROXY_CERT_LOCK_METHOD" flag:"cert-lock-method"`
	// WildcardCertDir is an optional directory containing static wildcard
	// certificates that override ACME for matching domains.
	WildcardCertDir string `yaml:"wildcardCertDir" env:"NB_PROXY_WILDCARD_CERT_DIR" flag:"wildcard-cert-dir"`

	// DebugEndpointEnabled toggles the debug HTTP endpoint.
	DebugEndpointEnabled bool `yaml:"debugEndpointEnabled" env:"NB_PROXY_DEBUG_ENDPOINT" flag:"debug-endpoint"`
	// DebugEndpointAddress is the bind address for the debug endpoint.
	DebugEndpointAddress string `yaml:"debugEndpointAddress" env:"NB_PROXY_DEBUG_ENDPOINT_ADDRESS" flag:"debug-endpoint-addr"`
	// HealthAddr is the bind address for the health probe and metrics
	// surface. Empty disables the health probe entirely (library callers
	// can attach their own).
	HealthAddr string `yaml:"healthAddress" env:"NB_PROXY_HEALTH_ADDRESS" flag:"health-addr"`

	// ForwardedProto overrides the X-Forwarded-Proto value sent to
	// backends. Valid values: "auto", "http", "https".
	ForwardedProto string `yaml:"forwardedProto" env:"NB_PROXY_FORWARDED_PROTO" flag:"forwarded-proto"`
	// TrustedProxies is the set of trusted upstream proxies that may set
	// forwarding headers.
	TrustedProxies *trustedproxy.List `yaml:"trustedProxies" env:"NB_PROXY_TRUSTED_PROXIES" flag:"trusted-proxies"`
	// WireguardPort is the UDP port for the embedded NetBird tunnel.
	// Zero asks the OS for a random port.
	WireguardPort uint16 `yaml:"wireguardPort" env:"NB_PROXY_WG_PORT" flag:"wg-port"`
	// ProxyProtocol enables PROXY protocol (v1/v2) on TCP listeners.
	ProxyProtocol bool `yaml:"proxyProtocol" env:"NB_PROXY_PROXY_PROTOCOL" flag:"proxy-protocol"`
	// PreSharedKey is the WireGuard pre-shared key used between the
	// proxy's embedded clients and peers.
	PreSharedKey string `yaml:"preSharedKey" env:"NB_PROXY_PRESHARED_KEY" flag:"preshared-key"`
	// Performance configures the tunnel pool/batch sizes for every
	// embedded client this proxy creates. Zero values fall back to
	// upstream defaults.
	Performance embed.Performance `yaml:"performance" env:"-" flag:"-"`

	// SupportsCustomPorts indicates whether the proxy can bind arbitrary
	// ports for TCP/UDP/TLS services.
	SupportsCustomPorts bool `yaml:"supportsCustomPorts" env:"NB_PROXY_SUPPORTS_CUSTOM_PORTS" flag:"supports-custom-ports"`
	// RequireSubdomain forces accounts to use a subdomain in front of
	// the proxy's cluster domain.
	RequireSubdomain bool `yaml:"requireSubdomain" env:"NB_PROXY_REQUIRE_SUBDOMAIN" flag:"require-subdomain"`
	// Private flags this proxy as embedded in a netbird client and
	// serving exclusively over the WireGuard tunnel. Also enables
	// per-account inbound listeners on each embedded client's netstack.
	Private bool `yaml:"private" env:"NB_PROXY_PRIVATE" flag:"private"`

	// MaxDialTimeout caps the per-service backend dial timeout.
	MaxDialTimeout time.Duration `yaml:"maxDialTimeout" env:"NB_PROXY_MAX_DIAL_TIMEOUT" flag:"max-dial-timeout"`
	// MaxSessionIdleTimeout caps the per-service session idle timeout.
	MaxSessionIdleTimeout time.Duration `yaml:"maxSessionIdleTimeout" env:"NB_PROXY_MAX_SESSION_IDLE_TIMEOUT" flag:"max-session-idle-timeout"`
	// MappingBatchWatchdog bounds how long a single mapping batch may spend
	// being applied before the receive loop reconnects to resync. Zero falls
	// back to the internal default.
	MappingBatchWatchdog time.Duration `yaml:"mappingBatchWatchdog" env:"NB_PROXY_MAPPING_BATCH_WATCHDOG"`

	// GeoDataDir is the directory containing GeoLite2 MMDB files.
	GeoDataDir string `yaml:"geoDataDir" env:"NB_PROXY_GEO_DATA_DIR" flag:"geo-data-dir"`
	// CrowdSecAPIURL is the CrowdSec LAPI URL. Empty disables CrowdSec.
	CrowdSecAPIURL string `yaml:"crowdSecAPIURL" env:"NB_PROXY_CROWDSEC_API_URL" flag:"crowdsec-api-url"`
	// CrowdSecAPIKey is the CrowdSec bouncer API key. Empty disables
	// CrowdSec.
	CrowdSecAPIKey string `yaml:"crowdSecAPIKey" env:"NB_PROXY_CROWDSEC_API_KEY" flag:"crowdsec-api-key"`
}

// New builds a Server from cfg without performing any I/O. No goroutines
// are spawned, no network connections are dialed, and no listeners are
// bound — call Start to bring the proxy up. Returning a fully-formed
// Server keeps the standalone code path (which still constructs Server
// directly) byte-for-byte equivalent.
func New(ctx context.Context, cfg Config) *Server {
	return &Server{
		ctx:                      ctx,
		ListenAddr:               cfg.ListenAddr,
		ID:                       cfg.ID,
		Logger:                   cfg.Logger,
		Version:                  cfg.Version,
		ProxyURL:                 cfg.ProxyURL,
		ManagementAddress:        cfg.ManagementAddress,
		ProxyToken:               cfg.ProxyToken,
		CertificateDirectory:     cfg.CertificateDirectory,
		CertificateFile:          cfg.CertificateFile,
		CertificateKeyFile:       cfg.CertificateKeyFile,
		GenerateACMECertificates: cfg.GenerateACMECertificates,
		ACMEChallengeAddress:     cfg.ACMEChallengeAddress,
		ACMEDirectory:            cfg.ACMEDirectory,
		ACMEEABKID:               cfg.ACMEEABKID,
		ACMEEABHMACKey:           cfg.ACMEEABHMACKey,
		ACMEChallengeType:        cfg.ACMEChallengeType,
		CertLockMethod:           cfg.CertLockMethod,
		WildcardCertDir:          cfg.WildcardCertDir,
		DebugEndpointEnabled:     cfg.DebugEndpointEnabled,
		DebugEndpointAddress:     cfg.DebugEndpointAddress,
		HealthAddress:            cfg.HealthAddr,
		ForwardedProto:           cfg.ForwardedProto,
		TrustedProxies:           cfg.TrustedProxies,
		WireguardPort:            cfg.WireguardPort,
		ProxyProtocol:            cfg.ProxyProtocol,
		PreSharedKey:             cfg.PreSharedKey,
		Performance:              cfg.Performance,
		SupportsCustomPorts:      cfg.SupportsCustomPorts,
		RequireSubdomain:         cfg.RequireSubdomain,
		Private:                  cfg.Private,
		MaxDialTimeout:           cfg.MaxDialTimeout,
		MaxSessionIdleTimeout:    cfg.MaxSessionIdleTimeout,
		MappingBatchWatchdog:     cfg.MappingBatchWatchdog,
		GeoDataDir:               cfg.GeoDataDir,
		CrowdSecAPIURL:           cfg.CrowdSecAPIURL,
		CrowdSecAPIKey:           cfg.CrowdSecAPIKey,
	}
}
