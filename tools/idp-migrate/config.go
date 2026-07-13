package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/netbirdio/netbird/util"
)

type migrationConfig struct {
	// Data
	dashboardURL string
	apiURL       string
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
	cfg, err := configFromArgs(os.Args[1:])
	if err != nil {
		return nil, err
	}

	if err := util.InitLog(cfg.logLevel, util.LogConsole); err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}

	return cfg, nil
}

func configFromArgs(args []string) (*migrationConfig, error) {
	var cfg migrationConfig
	var domain string

	fs := flag.NewFlagSet("netbird-idp-migrate", flag.ContinueOnError)
	fs.StringVar(&domain, "domain", "", "domain for both dashboard and API")
	fs.StringVar(&cfg.dashboardURL, "dashboard-url", "", "dashboard URL")
	fs.StringVar(&cfg.apiURL, "api-url", "", "API URL")
	fs.StringVar(&cfg.configPath, "config", "", "path to management.json (required)")
	fs.StringVar(&cfg.dataDir, "datadir", "", "override data directory from config")
	fs.StringVar(&cfg.idpSeedInfo, "idp-seed-info", "", "base64-encoded connector JSON (overrides auto-detection)")
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "preview changes without writing")
	fs.BoolVar(&cfg.force, "force", false, "skip confirmation prompt")
	fs.BoolVar(&cfg.skipConfig, "skip-config", false, "skip config generation (DB migration only)")
	fs.BoolVar(&cfg.skipPopulateUserInfo, "skip-populate-user-info", false, "skip populating user info (user id migration only)")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	if err := fs.Parse(args); err != nil {
		return nil, err
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
		if cfg.apiURL == "" {
			cfg.apiURL = domain
		}
		if cfg.dashboardURL == "" {
			cfg.dashboardURL = domain
		}
	}

	// Env vars override flags. Broad env var first, then narrow ones on top,
	// so the most granular value always wins.
	if val, ok := os.LookupEnv("NETBIRD_DOMAIN"); ok {
		cfg.dashboardURL = val
		cfg.apiURL = val
	}

	if val, ok := os.LookupEnv("NETBIRD_API_URL"); ok {
		cfg.apiURL = val
	}

	if val, ok := os.LookupEnv("NETBIRD_DASHBOARD_URL"); ok {
		cfg.dashboardURL = val
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

	// Enforce dry run if any value is provided
	if sval, ok := os.LookupEnv("NETBIRD_DRY_RUN"); ok {
		if val, err := strconv.ParseBool(sval); err == nil {
			cfg.dryRun = val
		}
	}

	cfg.dryRun = parseBool("NETBIRD_DRY_RUN", cfg.dryRun)
	cfg.force = parseBool("NETBIRD_FORCE", cfg.force)
	cfg.skipConfig = parseBool("NETBIRD_SKIP_CONFIG", cfg.skipConfig)
	cfg.skipPopulateUserInfo = parseBool("NETBIRD_SKIP_POPULATE_USER_INFO", cfg.skipPopulateUserInfo)

	if val, ok := os.LookupEnv("NETBIRD_LOG_LEVEL"); ok {
		cfg.logLevel = val
	}
}

func parseBool(varName string, defaultVal bool) bool {
	stringValue, ok := os.LookupEnv(varName)
	if !ok {
		return defaultVal
	}

	boolValue, err := strconv.ParseBool(stringValue)
	if err != nil {
		return defaultVal
	}

	return boolValue
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

	if cfg.apiURL == "" {
		return fmt.Errorf("--api-domain is required")
	}

	if cfg.dashboardURL == "" {
		return fmt.Errorf("--dashboard-domain is required")
	}

	return nil
}
