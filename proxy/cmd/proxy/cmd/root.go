package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"

	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/proxy"
	nbacme "github.com/netbirdio/netbird/proxy/internal/acme"
	"github.com/netbirdio/netbird/util"
)

const DefaultManagementURL = "https://api.netbird.io:443"

// envProxyToken is the environment variable name for the proxy access token.
//
//nolint:gosec
const envProxyToken = "NB_PROXY_TOKEN"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
	GoVersion = "unknown"
)

var (
	logLevel              string
	debugLogs             bool
	mgmtAddr              string
	addr                  string
	proxyDomain           string
	maxDialTimeout        time.Duration
	maxSessionIdleTimeout time.Duration
	certDir               string
	acmeCerts             bool
	acmeAddr              string
	acmeDir               string
	acmeEABKID            string
	acmeEABHMACKey        string
	acmeChallengeType     string
	debugEndpoint         bool
	debugEndpointAddr     string
	healthAddr            string
	forwardedProto        string
	trustedProxies        string
	certFile              string
	certKeyFile           string
	certLockMethod        string
	wildcardCertDir       string
	wgPort                uint16
	proxyProtocol         bool
	preSharedKey          string
	supportsCustomPorts   bool
	requireSubdomain      bool
	geoDataDir            string
	crowdsecAPIURL        string
	crowdsecAPIKey        string
)

var rootCmd = &cobra.Command{
	Use:          "proxy",
	Short:        "NetBird reverse proxy server",
	Long:         "NetBird reverse proxy server for proxying traffic to NetBird networks.",
	Version:      Version,
	SilenceUsage: true,
	RunE:         runServer,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", envStringOrDefault("NB_PROXY_LOG_LEVEL", "info"), "Log level: panic, fatal, error, warn, info, debug, trace")
	rootCmd.PersistentFlags().BoolVar(&debugLogs, "debug", envBoolOrDefault("NB_PROXY_DEBUG_LOGS", false), "Enable debug logs")
	_ = rootCmd.PersistentFlags().MarkDeprecated("debug", "use --log-level instead")
	rootCmd.Flags().StringVar(&mgmtAddr, "mgmt", envStringOrDefault("NB_PROXY_MANAGEMENT_ADDRESS", DefaultManagementURL), "Management address to connect to")
	rootCmd.Flags().StringVar(&addr, "addr", envStringOrDefault("NB_PROXY_ADDRESS", ":443"), "Reverse proxy address to listen on")
	rootCmd.Flags().StringVar(&proxyDomain, "domain", envStringOrDefault("NB_PROXY_DOMAIN", ""), "The Domain at which this proxy will be reached. e.g., netbird.example.com")
	rootCmd.Flags().StringVar(&certDir, "cert-dir", envStringOrDefault("NB_PROXY_CERTIFICATE_DIRECTORY", "./certs"), "Directory to store certificates")
	rootCmd.Flags().BoolVar(&acmeCerts, "acme-certs", envBoolOrDefault("NB_PROXY_ACME_CERTIFICATES", false), "Generate ACME certificates automatically")
	rootCmd.Flags().StringVar(&acmeAddr, "acme-addr", envStringOrDefault("NB_PROXY_ACME_ADDRESS", ":80"), "HTTP address for ACME HTTP-01 challenges (only used when acme-challenge-type is http-01)")
	rootCmd.Flags().StringVar(&acmeDir, "acme-dir", envStringOrDefault("NB_PROXY_ACME_DIRECTORY", acme.LetsEncryptURL), "URL of ACME challenge directory")
	rootCmd.Flags().StringVar(&acmeEABKID, "acme-eab-kid", envStringOrDefault("NB_PROXY_ACME_EAB_KID", ""), "ACME EAB KID for account registration")
	rootCmd.Flags().StringVar(&acmeEABHMACKey, "acme-eab-hmac-key", envStringOrDefault("NB_PROXY_ACME_EAB_HMAC_KEY", ""), "ACME EAB HMAC key for account registration")
	rootCmd.Flags().StringVar(&acmeChallengeType, "acme-challenge-type", envStringOrDefault("NB_PROXY_ACME_CHALLENGE_TYPE", "tls-alpn-01"), "ACME challenge type: tls-alpn-01 (default, port 443 only) or http-01 (requires port 80)")
	rootCmd.Flags().BoolVar(&debugEndpoint, "debug-endpoint", envBoolOrDefault("NB_PROXY_DEBUG_ENDPOINT", false), "Enable debug HTTP endpoint")
	rootCmd.Flags().StringVar(&debugEndpointAddr, "debug-endpoint-addr", envStringOrDefault("NB_PROXY_DEBUG_ENDPOINT_ADDRESS", "localhost:8444"), "Address for the debug HTTP endpoint")
	rootCmd.Flags().StringVar(&healthAddr, "health-addr", envStringOrDefault("NB_PROXY_HEALTH_ADDRESS", "localhost:8080"), "Address for the health probe endpoint (liveness/readiness/startup)")
	rootCmd.Flags().StringVar(&forwardedProto, "forwarded-proto", envStringOrDefault("NB_PROXY_FORWARDED_PROTO", "auto"), "X-Forwarded-Proto value for backends: auto, http, or https")
	rootCmd.Flags().StringVar(&trustedProxies, "trusted-proxies", envStringOrDefault("NB_PROXY_TRUSTED_PROXIES", ""), "Comma-separated list of trusted upstream proxy CIDR ranges (e.g. '10.0.0.0/8,192.168.1.1')")
	rootCmd.Flags().StringVar(&certFile, "cert-file", envStringOrDefault("NB_PROXY_CERTIFICATE_FILE", "tls.crt"), "TLS certificate filename within the certificate directory")
	rootCmd.Flags().StringVar(&certKeyFile, "cert-key-file", envStringOrDefault("NB_PROXY_CERTIFICATE_KEY_FILE", "tls.key"), "TLS certificate key filename within the certificate directory")
	rootCmd.Flags().StringVar(&certLockMethod, "cert-lock-method", envStringOrDefault("NB_PROXY_CERT_LOCK_METHOD", "auto"), "Certificate lock method for cross-replica coordination: auto, flock, or k8s-lease")
	rootCmd.Flags().StringVar(&wildcardCertDir, "wildcard-cert-dir", envStringOrDefault("NB_PROXY_WILDCARD_CERT_DIR", ""), "Directory containing wildcard certificate pairs (<name>.crt/<name>.key). Wildcard patterns are extracted from SANs automatically")
	rootCmd.Flags().Uint16Var(&wgPort, "wg-port", envUint16OrDefault("NB_PROXY_WG_PORT", 0), "WireGuard listen port (0 = random). Fixed port only works with single-account deployments")
	rootCmd.Flags().BoolVar(&proxyProtocol, "proxy-protocol", envBoolOrDefault("NB_PROXY_PROXY_PROTOCOL", false), "Enable PROXY protocol on TCP listeners to preserve client IPs behind L4 proxies")
	rootCmd.Flags().StringVar(&preSharedKey, "preshared-key", envStringOrDefault("NB_PROXY_PRESHARED_KEY", ""), "Define a pre-shared key for the tunnel between proxy and peers")
	rootCmd.Flags().BoolVar(&supportsCustomPorts, "supports-custom-ports", envBoolOrDefault("NB_PROXY_SUPPORTS_CUSTOM_PORTS", true), "Whether the proxy can bind arbitrary ports for UDP/TCP passthrough")
	rootCmd.Flags().BoolVar(&requireSubdomain, "require-subdomain", envBoolOrDefault("NB_PROXY_REQUIRE_SUBDOMAIN", false), "Require a subdomain label in front of the cluster domain")
	rootCmd.Flags().DurationVar(&maxDialTimeout, "max-dial-timeout", envDurationOrDefault("NB_PROXY_MAX_DIAL_TIMEOUT", 0), "Cap per-service backend dial timeout (0 = no cap)")
	rootCmd.Flags().DurationVar(&maxSessionIdleTimeout, "max-session-idle-timeout", envDurationOrDefault("NB_PROXY_MAX_SESSION_IDLE_TIMEOUT", 0), "Cap per-service session idle timeout (0 = no cap)")
	rootCmd.Flags().StringVar(&geoDataDir, "geo-data-dir", envStringOrDefault("NB_PROXY_GEO_DATA_DIR", "/var/lib/netbird/geolocation"), "Directory for the GeoLite2 MMDB file (auto-downloaded if missing)")
	rootCmd.Flags().StringVar(&crowdsecAPIURL, "crowdsec-api-url", envStringOrDefault("NB_PROXY_CROWDSEC_API_URL", ""), "CrowdSec LAPI URL for IP reputation checks")
	rootCmd.Flags().StringVar(&crowdsecAPIKey, "crowdsec-api-key", envStringOrDefault("NB_PROXY_CROWDSEC_API_KEY", ""), "CrowdSec bouncer API key")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SetVersionInfo sets version information for the CLI.
func SetVersionInfo(version, commit, buildDate, goVersion string) {
	Version = version
	Commit = commit
	BuildDate = buildDate
	GoVersion = goVersion
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("Version: {{.Version}}, Commit: " + Commit + ", BuildDate: " + BuildDate + ", Go: " + GoVersion + "\n")
}

func runServer(cmd *cobra.Command, args []string) error {
	proxyToken := os.Getenv(envProxyToken)
	if proxyToken == "" {
		return fmt.Errorf("proxy token is required: set %s environment variable", envProxyToken)
	}

	level := logLevel
	if debugLogs {
		level = "debug"
	}
	logger := log.New()

	_ = util.InitLogger(logger, level, util.LogConsole)

	logger.Infof("configured log level: %s", level)

	switch forwardedProto {
	case "auto", "http", "https":
	default:
		return fmt.Errorf("invalid --forwarded-proto value %q: must be auto, http, or https", forwardedProto)
	}

	_, err := domain.ValidateDomains([]string{proxyDomain})
	if err != nil {
		return fmt.Errorf("invalid domain value %q: %w", proxyDomain, err)
	}

	parsedTrustedProxies, err := proxy.ParseTrustedProxies(trustedProxies)
	if err != nil {
		return fmt.Errorf("invalid --trusted-proxies: %w", err)
	}

	srv := proxy.Server{
		Logger:                   logger,
		Version:                  Version,
		ManagementAddress:        mgmtAddr,
		ProxyURL:                 proxyDomain,
		ProxyToken:               proxyToken,
		CertificateDirectory:     certDir,
		CertificateFile:          certFile,
		CertificateKeyFile:       certKeyFile,
		GenerateACMECertificates: acmeCerts,
		ACMEChallengeAddress:     acmeAddr,
		ACMEDirectory:            acmeDir,
		ACMEEABKID:               acmeEABKID,
		ACMEEABHMACKey:           acmeEABHMACKey,
		ACMEChallengeType:        acmeChallengeType,
		DebugEndpointEnabled:     debugEndpoint,
		DebugEndpointAddress:     debugEndpointAddr,
		HealthAddress:            healthAddr,
		ForwardedProto:           forwardedProto,
		TrustedProxies:           parsedTrustedProxies,
		CertLockMethod:           nbacme.CertLockMethod(certLockMethod),
		WildcardCertDir:          wildcardCertDir,
		WireguardPort:            wgPort,
		ProxyProtocol:            proxyProtocol,
		PreSharedKey:             preSharedKey,
		SupportsCustomPorts:      supportsCustomPorts,
		RequireSubdomain:         requireSubdomain,
		MaxDialTimeout:           maxDialTimeout,
		MaxSessionIdleTimeout:    maxSessionIdleTimeout,
		GeoDataDir:               geoDataDir,
		CrowdSecAPIURL:           crowdsecAPIURL,
		CrowdSecAPIKey:           crowdsecAPIKey,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	return srv.ListenAndServe(ctx, addr)
}

func envBoolOrDefault(key string, def bool) bool {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		log.Warnf("parse %s=%q: %v, using default %v", key, v, err, def)
		return def
	}
	return parsed
}

func envStringOrDefault(key string, def string) string {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	return v
}

func envUint16OrDefault(key string, def uint16) uint16 {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	parsed, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		log.Warnf("parse %s=%q: %v, using default %d", key, v, err, def)
		return def
	}
	return uint16(parsed)
}

func envDurationOrDefault(key string, def time.Duration) time.Duration {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		log.Warnf("parse %s=%q: %v, using default %s", key, v, err, def)
		return def
	}
	return parsed
}
