// Package cmd implements the cobra root command for the dns01-spike binary.
package cmd

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/proxy/internal/acme/legoclient"
)

// letsEncryptStagingURL is the Let's Encrypt staging ACME directory URL.
// The spike pins staging by default to avoid burning real-world rate
// limits during exploratory runs. Override via SPIKE_ACME_DIR if needed.
const letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

var (
	flagDomain     string
	flagEmail      string
	flagToken      string
	flagOutputDir  string
	flagACMEDir    string
	flagLogLevel   string
)

var rootCmd = &cobra.Command{
	Use:   "dns01-spike",
	Short: "Spike: issue a Let's Encrypt cert via Lego + Cloudflare DNS-01",
	Long: `dns01-spike is a vertical-slice proof of concept for the DNS-01
roadmap (see roadmap.md and p1-plan.md). It uses Lego with the Cloudflare
provider to issue a real Let's Encrypt cert for a domain you control,
without requiring the proxy to be publicly reachable.

The spike pins Let's Encrypt staging by default. Switch to production
only after verifying staging works end-to-end.

REQUIRED env vars (or flags):
  CF_DNS_API_TOKEN   Cloudflare API token, scoped to Zone:DNS:Edit for
                     the target zone. Do NOT use the global API key.
  SPIKE_DOMAIN       FQDN to issue for, e.g. test.example.com
  SPIKE_EMAIL        ACME account email

OPTIONAL:
  SPIKE_OUTPUT_DIR   Directory for cert + account state (default ./certs-spike)
  SPIKE_ACME_DIR     ACME directory URL (default Let's Encrypt staging)`,
	SilenceUsage: true,
	RunE:         run,
}

func init() {
	rootCmd.Flags().StringVar(&flagDomain, "domain", envOrDefault("SPIKE_DOMAIN", ""), "FQDN to issue cert for (env: SPIKE_DOMAIN)")
	rootCmd.Flags().StringVar(&flagEmail, "email", envOrDefault("SPIKE_EMAIL", ""), "ACME account email (env: SPIKE_EMAIL)")
	rootCmd.Flags().StringVar(&flagToken, "cf-token", envOrDefault("CF_DNS_API_TOKEN", ""), "Cloudflare API token, Zone:DNS:Edit scope (env: CF_DNS_API_TOKEN)")
	rootCmd.Flags().StringVar(&flagOutputDir, "output", envOrDefault("SPIKE_OUTPUT_DIR", "./certs-spike"), "Output directory for cert + account state (env: SPIKE_OUTPUT_DIR)")
	rootCmd.Flags().StringVar(&flagACMEDir, "acme-dir", envOrDefault("SPIKE_ACME_DIR", letsEncryptStagingURL), "ACME directory URL (env: SPIKE_ACME_DIR; default: Let's Encrypt staging)")
	rootCmd.Flags().StringVar(&flagLogLevel, "log-level", envOrDefault("SPIKE_LOG_LEVEL", "info"), "Log level: debug, info, warn, error")
}

func run(_ *cobra.Command, _ []string) error {
	logger := log.StandardLogger()
	level, err := log.ParseLevel(flagLogLevel)
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}
	logger.SetLevel(level)

	if flagDomain == "" {
		return fmt.Errorf("--domain (or SPIKE_DOMAIN) is required")
	}
	if flagEmail == "" {
		return fmt.Errorf("--email (or SPIKE_EMAIL) is required")
	}
	if flagToken == "" {
		return fmt.Errorf("--cf-token (or CF_DNS_API_TOKEN) is required")
	}

	logger.Infof("[spike] domain=%s email=%s output=%s acme=%s", flagDomain, flagEmail, flagOutputDir, flagACMEDir)
	if flagACMEDir == letsEncryptStagingURL {
		logger.Warn("[spike] using Let's Encrypt STAGING — issued certs will not be browser-trusted (this is intentional for the spike)")
	} else {
		logger.Warnf("[spike] using non-staging ACME directory %q — make sure you understand rate limits", flagACMEDir)
	}

	cli, err := legoclient.New(legoclient.Config{
		StorageDir:         flagOutputDir,
		ACMEDirectoryURL:   flagACMEDir,
		AccountEmail:       flagEmail,
		CloudflareAPIToken: flagToken,
		Logger:             logger,
	})
	if err != nil {
		return fmt.Errorf("build lego client: %w", err)
	}

	if err := cli.IssueCertificate(context.Background(), flagDomain); err != nil {
		return fmt.Errorf("issue certificate: %w", err)
	}

	logger.Infof("[spike] done. inspect %s/%s.crt to see the issued cert", flagOutputDir, flagDomain)
	logger.Infof("[spike] try: openssl x509 -in %s/%s.crt -text -noout | head -20", flagOutputDir, flagDomain)
	return nil
}

// Execute runs the cobra root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func envOrDefault(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}
