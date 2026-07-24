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
	ListenAddr string
	// PublicPort is the external port forwarded to the main listener. It lets
	// TLS passthrough mappings share the main SNI router when an ingress proxy
	// translates ports, for example public 443 to internal 8443.
	PublicPort uint16
	// ID identifies this proxy instance to management. Empty values are
	// replaced with a timestamped default at Server.Start time (see
	// initDefaults), not in New.
	ID string
	// Logger is the logrus logger used everywhere. Empty values fall
	// back to log.StandardLogger() at Server.Start time (see
	// initDefaults), not in New.
	Logger *log.Logger
	// Version is the build version string reported to management. Empty
	// values are replaced with "dev" at Server.Start time (see
	// initDefaults), not in New.
	Version string
	// ProxyURL is the public address operators use to reach this proxy.
	ProxyURL string
	// ManagementAddress is the gRPC URL of the management server.
	ManagementAddress string
	// ProxyToken authenticates this proxy with the management server.
	ProxyToken string

	// CertificateDirectory is the directory holding TLS certificate
	// material (static or ACME-provisioned).
	CertificateDirectory string
	// CertificateFile is the certificate filename within
	// CertificateDirectory.
	CertificateFile string
	// CertificateKeyFile is the private key filename within
	// CertificateDirectory.
	CertificateKeyFile string
	// GenerateACMECertificates toggles ACME certificate provisioning.
	GenerateACMECertificates bool
	// ACMEChallengeAddress is the listen address for HTTP-01 challenges.
	ACMEChallengeAddress string
	// ACMEDirectory is the ACME directory URL (Let's Encrypt by default).
	ACMEDirectory string
	// ACMEEABKID is the External Account Binding Key ID for CAs that
	// require EAB (e.g. ZeroSSL).
	ACMEEABKID string
	// ACMEEABHMACKey is the External Account Binding HMAC key for CAs
	// that require EAB.
	ACMEEABHMACKey string
	// ACMEChallengeType is the ACME challenge type ("tls-alpn-01" or
	// "http-01"). Empty defaults to "tls-alpn-01".
	ACMEChallengeType string
	// CertLockMethod controls how ACME certificate locks are coordinated
	// across replicas.
	CertLockMethod acme.CertLockMethod
	// WildcardCertDir is an optional directory containing static wildcard
	// certificates that override ACME for matching domains.
	WildcardCertDir string

	// DebugEndpointEnabled toggles the debug HTTP endpoint.
	DebugEndpointEnabled bool
	// DebugEndpointAddress is the bind address for the debug endpoint.
	DebugEndpointAddress string
	// HealthAddr is the bind address for the health probe and metrics
	// surface. Empty disables the health probe entirely (library callers
	// can attach their own).
	HealthAddr string

	// ForwardedProto overrides the X-Forwarded-Proto value sent to
	// backends. Valid values: "auto", "http", "https".
	ForwardedProto string
	// TrustedProxies is the set of trusted upstream proxies that may set
	// forwarding headers.
	TrustedProxies *trustedproxy.List
	// WireguardPort is the UDP port for the embedded NetBird tunnel.
	// Zero asks the OS for a random port.
	WireguardPort uint16
	// ProxyProtocol enables PROXY protocol (v1/v2) on TCP listeners.
	ProxyProtocol bool
	// PreSharedKey is the WireGuard pre-shared key used between the
	// proxy's embedded clients and peers.
	PreSharedKey string
	// Performance configures the tunnel pool/batch sizes for every
	// embedded client this proxy creates. Zero values fall back to
	// upstream defaults.
	Performance embed.Performance

	// SupportsCustomPorts indicates whether the proxy can bind arbitrary
	// ports for TCP/UDP/TLS services.
	SupportsCustomPorts bool
	// RequireSubdomain forces accounts to use a subdomain in front of
	// the proxy's cluster domain.
	RequireSubdomain bool
	// Private flags this proxy as embedded in a netbird client and
	// serving exclusively over the WireGuard tunnel. Also enables
	// per-account inbound listeners on each embedded client's netstack.
	Private bool

	// MaxDialTimeout caps the per-service backend dial timeout.
	MaxDialTimeout time.Duration
	// MaxSessionIdleTimeout caps the per-service session idle timeout.
	MaxSessionIdleTimeout time.Duration
	// MappingBatchWatchdog bounds how long a single mapping batch may spend
	// being applied before the receive loop reconnects to resync. Zero falls
	// back to the internal default.
	MappingBatchWatchdog time.Duration

	// GeoDataDir is the directory containing GeoLite2 MMDB files.
	GeoDataDir string
	// CrowdSecAPIURL is the CrowdSec LAPI URL. Empty disables CrowdSec.
	CrowdSecAPIURL string
	// CrowdSecAPIKey is the CrowdSec bouncer API key. Empty disables
	// CrowdSec.
	CrowdSecAPIKey string
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
		mainPublicPort:           cfg.PublicPort,
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
