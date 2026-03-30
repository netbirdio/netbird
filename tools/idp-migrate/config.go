package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/netbirdio/netbird/util"
)

type migrationConfig struct {
	// Data
	dashboardUrl string
	apiUrl       string
	configPath   string
	dataDir      string
	idpSeedInfo  string

	// Options
	dryRun               bool
	force                bool
	skipConfig           bool
	skipPopulateUserInfo bool

	// Logging
	logLevel string
}

func config() (*migrationConfig, error) {
	var cfg migrationConfig

	var domain string
	flag.StringVar(&domain, "domain", "", "domain for both dashboard and API")
	flag.StringVar(&cfg.dashboardUrl, "dashboard-domain", "", "dashboard domain")
	flag.StringVar(&cfg.apiUrl, "api-domain", "", "API domain")
	flag.StringVar(&cfg.configPath, "config", "", "path to management.json (required)")
	flag.StringVar(&cfg.dataDir, "datadir", "", "override data directory from config")
	flag.StringVar(&cfg.idpSeedInfo, "idp-seed-info", "", "base64-encoded connector JSON (overrides auto-detection)")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "preview changes without writing")
	flag.BoolVar(&cfg.force, "force", false, "skip confirmation prompt")
	flag.BoolVar(&cfg.skipConfig, "skip-config", false, "skip config generation (DB migration only)")
	flag.BoolVar(&cfg.skipPopulateUserInfo, "skip-populate-user-info", false, "skip populating user info (user id migration only)")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	flag.Parse()

	if err := util.InitLog(cfg.logLevel, util.LogConsole); err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}

	applyOverrides(&cfg, domain)

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil

}

// applyOverrides resolves domain configuration from broad to narrow sources.
// The most granular value always wins:
//
//	--domain flag (broadest, only fills blanks)
//	NETBIRD_DOMAIN env (overrides flags, sets both)
//	--api-domain / --dashboard-domain flags (more specific than --domain)
//	NETBIRD_API_URL / NETBIRD_DASHBOARD_URL env (most specific, always wins)
//
// Other env vars unconditionally override their corresponding flags.
func applyOverrides(cfg *migrationConfig, domain string) {
	// --domain is a convenience shorthand: only fills in values not already
	// set by the more specific --api-domain / --dashboard-domain flags.
	if domain != "" {
		if cfg.apiUrl == "" {
			cfg.apiUrl = domain
		}
		if cfg.dashboardUrl == "" {
			cfg.dashboardUrl = domain
		}
	}

	// Env vars override flags. Broad env var first, then narrow ones on top,
	// so the most granular value always wins.
	if val, ok := os.LookupEnv("NETBIRD_DOMAIN"); ok {
		cfg.dashboardUrl = val
		cfg.apiUrl = val
	}

	if val, ok := os.LookupEnv("NETBIRD_API_URL"); ok {
		cfg.apiUrl = val
	}

	if val, ok := os.LookupEnv("NETBIRD_DASHBOARD_URL"); ok {
		cfg.dashboardUrl = val
	}

	if val, ok := os.LookupEnv("NETBIRD_CONFIG_PATH"); ok {
		cfg.configPath = val
	}

	if val, ok := os.LookupEnv("NETBIRD_DATA_DIR"); ok {
		cfg.dataDir = val
	}

	if val, ok := os.LookupEnv("NETBIRD_IDP_SEED_INFO"); ok {
		cfg.idpSeedInfo = val
	}

	if val, ok := os.LookupEnv("NETBIRD_DRY_RUN"); ok {
		cfg.dryRun = val == "true"
	}

	if val, ok := os.LookupEnv("NETBIRD_FORCE"); ok {
		cfg.force = val == "true"
	}

	if val, ok := os.LookupEnv("NETBIRD_SKIP_CONFIG"); ok {
		cfg.skipConfig = val == "true"
	}

	if val, ok := os.LookupEnv("NETBIRD_SKIP_POPULATE_USER_INFO"); ok {
		cfg.skipPopulateUserInfo = val == "true"
	}

	if val, ok := os.LookupEnv("NETBIRD_LOG_LEVEL"); ok {
		cfg.logLevel = val
	}
}

func validateConfig(cfg *migrationConfig) error {
	if cfg.configPath == "" {
		return fmt.Errorf("--config is required")
	}

	if cfg.dataDir == "" {
		return fmt.Errorf("--datadir is required")
	}

	if cfg.idpSeedInfo == "" {
		return fmt.Errorf("--idp-seed-info is required")
	}

	if cfg.apiUrl == "" {
		return fmt.Errorf("--api-domain is required")
	}

	if cfg.dashboardUrl == "" {
		return fmt.Errorf("--dashboard-domain is required")
	}

	return nil
}
