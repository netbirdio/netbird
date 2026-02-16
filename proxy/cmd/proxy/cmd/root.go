package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/netbirdio/netbird/shared/management/domain"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"

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
	debugLogs         bool
	mgmtAddr          string
	addr              string
	proxyDomain       string
	certDir           string
	acmeCerts         bool
	acmeAddr          string
	acmeDir           string
	acmeChallengeType string
	debugEndpoint     bool
	debugEndpointAddr string
	healthAddr        string
	oidcClientID      string
	oidcClientSecret  string
	oidcEndpoint      string
	oidcScopes        string
	forwardedProto    string
	trustedProxies    string
	certFile          string
	certKeyFile       string
	certLockMethod    string
	wgPort            int
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
	rootCmd.PersistentFlags().BoolVar(&debugLogs, "debug", envBoolOrDefault("NB_PROXY_DEBUG_LOGS", false), "Enable debug logs")
	rootCmd.Flags().StringVar(&mgmtAddr, "mgmt", envStringOrDefault("NB_PROXY_MANAGEMENT_ADDRESS", DefaultManagementURL), "Management address to connect to")
	rootCmd.Flags().StringVar(&addr, "addr", envStringOrDefault("NB_PROXY_ADDRESS", ":443"), "Reverse proxy address to listen on")
	rootCmd.Flags().StringVar(&proxyDomain, "domain", envStringOrDefault("NB_PROXY_DOMAIN", ""), "The Domain at which this proxy will be reached. e.g., netbird.example.com")
	rootCmd.Flags().StringVar(&certDir, "cert-dir", envStringOrDefault("NB_PROXY_CERTIFICATE_DIRECTORY", "./certs"), "Directory to store certificates")
	rootCmd.Flags().BoolVar(&acmeCerts, "acme-certs", envBoolOrDefault("NB_PROXY_ACME_CERTIFICATES", false), "Generate ACME certificates automatically")
	rootCmd.Flags().StringVar(&acmeAddr, "acme-addr", envStringOrDefault("NB_PROXY_ACME_ADDRESS", ":80"), "HTTP address for ACME HTTP-01 challenges (only used when acme-challenge-type is http-01)")
	rootCmd.Flags().StringVar(&acmeDir, "acme-dir", envStringOrDefault("NB_PROXY_ACME_DIRECTORY", acme.LetsEncryptURL), "URL of ACME challenge directory")
	rootCmd.Flags().StringVar(&acmeChallengeType, "acme-challenge-type", envStringOrDefault("NB_PROXY_ACME_CHALLENGE_TYPE", "tls-alpn-01"), "ACME challenge type: tls-alpn-01 (default, port 443 only) or http-01 (requires port 80)")
	rootCmd.Flags().BoolVar(&debugEndpoint, "debug-endpoint", envBoolOrDefault("NB_PROXY_DEBUG_ENDPOINT", false), "Enable debug HTTP endpoint")
	rootCmd.Flags().StringVar(&debugEndpointAddr, "debug-endpoint-addr", envStringOrDefault("NB_PROXY_DEBUG_ENDPOINT_ADDRESS", "localhost:8444"), "Address for the debug HTTP endpoint")
	rootCmd.Flags().StringVar(&healthAddr, "health-addr", envStringOrDefault("NB_PROXY_HEALTH_ADDRESS", "localhost:8080"), "Address for the health probe endpoint (liveness/readiness/startup)")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-id", envStringOrDefault("NB_PROXY_OIDC_CLIENT_ID", "netbird-proxy"), "The OAuth2 Client ID for OIDC User Authentication")
	rootCmd.Flags().StringVar(&oidcClientSecret, "oidc-secret", envStringOrDefault("NB_PROXY_OIDC_CLIENT_SECRET", ""), "The OAuth2 Client Secret for OIDC User Authentication")
	rootCmd.Flags().StringVar(&oidcEndpoint, "oidc-endpoint", envStringOrDefault("NB_PROXY_OIDC_ENDPOINT", ""), "The OIDC Endpoint for OIDC User Authentication")
	rootCmd.Flags().StringVar(&oidcScopes, "oidc-scopes", envStringOrDefault("NB_PROXY_OIDC_SCOPES", "openid,profile,email"), "The OAuth2 scopes for OIDC User Authentication, comma separated")
	rootCmd.Flags().StringVar(&forwardedProto, "forwarded-proto", envStringOrDefault("NB_PROXY_FORWARDED_PROTO", "auto"), "X-Forwarded-Proto value for backends: auto, http, or https")
	rootCmd.Flags().StringVar(&trustedProxies, "trusted-proxies", envStringOrDefault("NB_PROXY_TRUSTED_PROXIES", ""), "Comma-separated list of trusted upstream proxy CIDR ranges (e.g. '10.0.0.0/8,192.168.1.1')")
	rootCmd.Flags().StringVar(&certFile, "cert-file", envStringOrDefault("NB_PROXY_CERTIFICATE_FILE", "tls.crt"), "TLS certificate filename within the certificate directory")
	rootCmd.Flags().StringVar(&certKeyFile, "cert-key-file", envStringOrDefault("NB_PROXY_CERTIFICATE_KEY_FILE", "tls.key"), "TLS certificate key filename within the certificate directory")
	rootCmd.Flags().StringVar(&certLockMethod, "cert-lock-method", envStringOrDefault("NB_PROXY_CERT_LOCK_METHOD", "auto"), "Certificate lock method for cross-replica coordination: auto, flock, or k8s-lease")
	rootCmd.Flags().IntVar(&wgPort, "wg-port", envIntOrDefault("NB_PROXY_WG_PORT", 0), "WireGuard listen port (0 = random). Fixed port only works with single-account deployments")
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

	level := "error"
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
		ACMEChallengeType:        acmeChallengeType,
		DebugEndpointEnabled:     debugEndpoint,
		DebugEndpointAddress:     debugEndpointAddr,
		HealthAddress:            healthAddr,
		OIDCClientId:             oidcClientID,
		OIDCClientSecret:         oidcClientSecret,
		OIDCEndpoint:             oidcEndpoint,
		OIDCScopes:               strings.Split(oidcScopes, ","),
		ForwardedProto:           forwardedProto,
		TrustedProxies:           parsedTrustedProxies,
		CertLockMethod:           nbacme.CertLockMethod(certLockMethod),
		WireguardPort:            wgPort,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := srv.ListenAndServe(ctx, addr); err != nil {
		logger.Error(err)
		return err
	}
	return nil
}

func envBoolOrDefault(key string, def bool) bool {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
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

func envIntOrDefault(key string, def int) int {
	v, exists := os.LookupEnv(key)
	if !exists {
		return def
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return parsed
}
