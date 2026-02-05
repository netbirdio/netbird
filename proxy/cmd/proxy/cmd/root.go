package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"

	"github.com/netbirdio/netbird/proxy"
	"github.com/netbirdio/netbird/util"
)

const DefaultManagementURL = "https://api.netbird.io:443"

// envProxyToken is the environment variable name for the proxy access token.
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
	proxyURL          string
	certDir           string
	acmeCerts         bool
	acmeAddr          string
	acmeDir           string
	debugEndpoint     bool
	debugEndpointAddr string
	healthAddr        string
	oidcClientID      string
	oidcClientSecret  string
	oidcEndpoint      string
	oidcScopes        string
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
	rootCmd.Flags().StringVar(&proxyURL, "url", envStringOrDefault("NB_PROXY_URL", ""), "The URL at which this proxy will be reached")
	rootCmd.Flags().StringVar(&certDir, "cert-dir", envStringOrDefault("NB_PROXY_CERTIFICATE_DIRECTORY", "./certs"), "Directory to store certificates")
	rootCmd.Flags().BoolVar(&acmeCerts, "acme-certs", envBoolOrDefault("NB_PROXY_ACME_CERTIFICATES", false), "Generate ACME certificates using HTTP-01 challenges")
	rootCmd.Flags().StringVar(&acmeAddr, "acme-addr", envStringOrDefault("NB_PROXY_ACME_ADDRESS", ":80"), "HTTP address for ACME HTTP-01 challenges")
	rootCmd.Flags().StringVar(&acmeDir, "acme-dir", envStringOrDefault("NB_PROXY_ACME_DIRECTORY", acme.LetsEncryptURL), "URL of ACME challenge directory")
	rootCmd.Flags().BoolVar(&debugEndpoint, "debug-endpoint", envBoolOrDefault("NB_PROXY_DEBUG_ENDPOINT", false), "Enable debug HTTP endpoint")
	rootCmd.Flags().StringVar(&debugEndpointAddr, "debug-endpoint-addr", envStringOrDefault("NB_PROXY_DEBUG_ENDPOINT_ADDRESS", "localhost:8444"), "Address for the debug HTTP endpoint")
	rootCmd.Flags().StringVar(&healthAddr, "health-addr", envStringOrDefault("NB_PROXY_HEALTH_ADDRESS", "localhost:8080"), "Address for the health probe endpoint (liveness/readiness/startup)")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-id", envStringOrDefault("NB_PROXY_OIDC_CLIENT_ID", "netbird-proxy"), "The OAuth2 Client ID for OIDC User Authentication")
	rootCmd.Flags().StringVar(&oidcClientSecret, "oidc-secret", envStringOrDefault("NB_PROXY_OIDC_CLIENT_SECRET", ""), "The OAuth2 Client Secret for OIDC User Authentication")
	rootCmd.Flags().StringVar(&oidcEndpoint, "oidc-endpoint", envStringOrDefault("NB_PROXY_OIDC_ENDPOINT", ""), "The OIDC Endpoint for OIDC User Authentication")
	rootCmd.Flags().StringVar(&oidcScopes, "oidc-scopes", envStringOrDefault("NB_PROXY_OIDC_SCOPES", "openid,profile,email"), "The OAuth2 scopes for OIDC User Authentication, comma separated")
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

	log.Infof("configured log level: %s", level)

	srv := proxy.Server{
		Logger:                   logger,
		Version:                  Version,
		ManagementAddress:        mgmtAddr,
		ProxyURL:                 proxyURL,
		ProxyToken:               proxyToken,
		CertificateDirectory:     certDir,
		GenerateACMECertificates: acmeCerts,
		ACMEChallengeAddress:     acmeAddr,
		ACMEDirectory:            acmeDir,
		DebugEndpointEnabled:     debugEndpoint,
		DebugEndpointAddress:     debugEndpointAddr,
		HealthAddress:            healthAddr,
		OIDCClientId:             oidcClientID,
		OIDCClientSecret:         oidcClientSecret,
		OIDCEndpoint:             oidcEndpoint,
		OIDCScopes:               strings.Split(oidcScopes, ","),
	}

	if err := srv.ListenAndServe(context.TODO(), addr); err != nil {
		log.Fatal(err)
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
