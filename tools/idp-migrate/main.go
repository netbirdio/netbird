// Package main provides a standalone CLI tool to migrate user IDs from an
// external IdP format to the embedded Dex IdP format used by NetBird >= v0.60.0.
//
// This tool reads management.json to auto-detect the current external IdP
// configuration (issuer, clientID, clientSecret, type) and re-encodes all user
// IDs in the database to the Dex protobuf-encoded format. It works independently
// of migrate.sh and the combined server, allowing operators to migrate their
// database before switching to the combined server.
//
// Usage:
//
//	netbird-idp-migrate --config /etc/netbird/management.json [--dry-run] [--force]
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp/migration"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"
)

// migrationServer implements migration.Server by wrapping the migration-specific interfaces.
type migrationServer struct {
	store      migration.MigrationStore
	eventStore migration.MigrationEventStore
}

func (s *migrationServer) Store() migration.MigrationStore        { return s.store }
func (s *migrationServer) EventStore() migration.MigrationEventStore { return s.eventStore }

func main() {
	var (
		configPath  string
		dataDir     string
		idpSeedInfo string
		dryRun      bool
		force       bool
		skipConfig  bool
		logLevel    string
	)

	flag.StringVar(&configPath, "config", "", "path to management.json (required)")
	flag.StringVar(&dataDir, "datadir", "", "override data directory from config")
	flag.StringVar(&idpSeedInfo, "idp-seed-info", "", "base64-encoded connector JSON (overrides auto-detection)")
	flag.BoolVar(&dryRun, "dry-run", false, "preview changes without writing")
	flag.BoolVar(&force, "force", false, "skip confirmation prompt")
	flag.BoolVar(&skipConfig, "skip-config", false, "skip config generation (DB migration only)")
	flag.StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	flag.Parse()

	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}

	if err := run(configPath, dataDir, idpSeedInfo, dryRun, force, skipConfig); err != nil {
		log.Fatalf("migration failed: %v", err)
	}
}

func run(configPath, dataDirOverride, idpSeedInfo string, dryRun, force, skipConfig bool) error {
	if configPath == "" {
		return fmt.Errorf("--config is required")
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	effectiveDataDir := cfg.Datadir
	if dataDirOverride != "" {
		effectiveDataDir = dataDirOverride
	}
	if effectiveDataDir == "" {
		return fmt.Errorf("data directory not set: use --datadir or set Datadir in management.json")
	}

	conn, err := resolveConnector(idpSeedInfo, cfg)
	if err != nil {
		return fmt.Errorf("resolve connector: %w", err)
	}
	if conn == nil {
		return fmt.Errorf("no connector configuration found: provide --idp-seed-info, set IDP_SEED_INFO env var, or configure IdpManagerConfig in management.json")
	}
	if conn.ID == "" {
		return fmt.Errorf("connector ID is empty")
	}

	log.Infof("resolved connector: type=%s, id=%s, name=%s", conn.Type, conn.ID, conn.Name)

	if err := migrateDB(cfg, effectiveDataDir, conn, dryRun, force); err != nil {
		return err
	}

	if skipConfig {
		log.Info("skipping config generation (--skip-config)")
		return nil
	}

	return generateConfig(configPath, conn, cfg, dryRun)
}

// openStores opens the main and activity stores, returning migration-specific interfaces.
// The caller must call the returned cleanup function to close the stores.
func openStores(ctx context.Context, cfg *nbconfig.Config, dataDir string) (migration.MigrationStore, migration.MigrationEventStore, func(), error) {
	engine := cfg.StoreConfig.Engine
	if engine == "" {
		engine = types.SqliteStoreEngine
	}

	mainStore, err := store.NewStore(ctx, engine, dataDir, nil, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open main store: %w", err)
	}

	if cfg.DataStoreEncryptionKey != "" {
		fieldEncrypt, err := crypt.NewFieldEncrypt(cfg.DataStoreEncryptionKey)
		if err != nil {
			_ = mainStore.Close(ctx)
			return nil, nil, nil, fmt.Errorf("init field encryption: %w", err)
		}
		mainStore.SetFieldEncrypt(fieldEncrypt)
	}

	migStore, ok := mainStore.(migration.MigrationStore)
	if !ok {
		_ = mainStore.Close(ctx)
		return nil, nil, nil, fmt.Errorf("store does not support migration operations (ListUsers/UpdateUserID)")
	}

	cleanup := func() { _ = mainStore.Close(ctx) }

	var migEventStore migration.MigrationEventStore
	actStore, err := activitystore.NewSqlStore(ctx, dataDir, cfg.DataStoreEncryptionKey)
	if err != nil {
		log.Warnf("could not open activity store (events.db may not exist): %v", err)
	} else {
		migEventStore = actStore
		prevCleanup := cleanup
		cleanup = func() { _ = actStore.Close(ctx); prevCleanup() }
	}

	return migStore, migEventStore, cleanup, nil
}

// migrateDB opens the stores, previews pending users, and runs the DB migration.
func migrateDB(cfg *nbconfig.Config, dataDir string, conn *dex.Connector, dryRun, force bool) error {
	ctx := context.Background()

	migStore, migEventStore, cleanup, err := openStores(ctx, cfg, dataDir)
	if err != nil {
		return err
	}
	defer cleanup()

	pending, err := previewUsers(ctx, migStore)
	if err != nil {
		return err
	}
	if pending == 0 {
		log.Info("no users need migration — all done")
		return nil
	}

	if dryRun {
		if err := os.Setenv("NB_IDP_MIGRATION_DRY_RUN", "true"); err != nil {
			return fmt.Errorf("set dry-run env: %w", err)
		}
		defer os.Unsetenv("NB_IDP_MIGRATION_DRY_RUN") //nolint:errcheck
	}

	if !dryRun && !force {
		if !confirmPrompt(pending) {
			log.Info("migration cancelled by user")
			return nil
		}
	}

	srv := &migrationServer{store: migStore, eventStore: migEventStore}
	if err := migration.MigrateUsersToStaticConnectors(srv, conn); err != nil {
		return fmt.Errorf("migrate users: %w", err)
	}

	if !dryRun {
		log.Info("DB migration completed successfully")
	}
	return nil
}

// previewUsers counts pending vs already-migrated users and logs a summary.
// Returns the number of users still needing migration.
func previewUsers(ctx context.Context, migStore migration.MigrationStore) (int, error) {
	users, err := migStore.ListUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("list users: %w", err)
	}

	var pending, alreadyMigrated int
	for _, u := range users {
		if _, _, decErr := dex.DecodeDexUserID(u.Id); decErr == nil {
			alreadyMigrated++
		} else {
			pending++
		}
	}

	log.Infof("found %d total users: %d pending migration, %d already migrated", len(users), pending, alreadyMigrated)
	return pending, nil
}

// confirmPrompt asks the user for interactive confirmation. Returns true if they accept.
func confirmPrompt(pending int) bool {
	fmt.Printf("About to migrate %d users. This cannot be easily undone. Continue? [y/N] ", pending)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

// loadConfig reads management.json into the management config struct.
func loadConfig(path string) (*nbconfig.Config, error) {
	cfg := &nbconfig.Config{}
	if _, err := util.ReadJsonWithEnvSub(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// resolveConnector determines the Dex connector using a three-tier priority:
//  1. --idp-seed-info flag (explicit base64-encoded JSON)
//  2. IDP_SEED_INFO env var
//  3. Auto-detect from management.json's IdpManagerConfig
func resolveConnector(flagValue string, cfg *nbconfig.Config) (*dex.Connector, error) {
	// Priority 1: explicit flag
	if flagValue != "" {
		return decodeConnector(flagValue)
	}

	// Priority 2: env var
	if migration.IsSeedInfoPresent() {
		return migration.SeedConnectorFromEnv()
	}

	// Priority 3: auto-detect from config
	return buildConnectorFromConfig(cfg)
}

// decodeConnector base64-decodes and JSON-unmarshals a connector.
func decodeConnector(encoded string) (*dex.Connector, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var conn dex.Connector
	if err := json.Unmarshal(decoded, &conn); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	return &conn, nil
}

// buildConnectorFromConfig constructs a Dex connector from management.json's
// IdpManagerConfig fields (issuer, clientID, clientSecret, type).
func buildConnectorFromConfig(cfg *nbconfig.Config) (*dex.Connector, error) {
	idpCfg := cfg.IdpManagerConfig
	if idpCfg == nil || idpCfg.ClientConfig == nil {
		return nil, nil
	}

	connType, err := mapManagerTypeToConnectorType(idpCfg.ManagerType)
	if err != nil {
		return nil, err
	}

	issuer := idpCfg.ClientConfig.Issuer
	if issuer == "" && cfg.HttpConfig != nil {
		issuer = cfg.HttpConfig.AuthIssuer
	}
	if issuer == "" {
		return nil, fmt.Errorf("could not determine OIDC issuer from config (neither ClientConfig.Issuer nor HttpConfig.AuthIssuer set)")
	}

	redirectURI := strings.TrimSuffix(issuer, "/") + "/oauth2/callback"

	connID := strings.ToLower(idpCfg.ManagerType)

	return &dex.Connector{
		Type: connType,
		Name: idpCfg.ManagerType,
		ID:   connID,
		Config: map[string]interface{}{
			"issuer":       issuer,
			"clientID":     idpCfg.ClientConfig.ClientID,
			"clientSecret": idpCfg.ClientConfig.ClientSecret,
			"redirectURI":  redirectURI,
		},
	}, nil
}

// mapManagerTypeToConnectorType maps management.json ManagerType values to the
// connector type strings that Dex uses. These must match the types in
// idp/dex/connector.go's buildStorageConnector switch.
func mapManagerTypeToConnectorType(managerType string) (string, error) {
	switch strings.ToLower(managerType) {
	case "zitadel":
		return "zitadel", nil
	case "keycloak":
		return "keycloak", nil
	case "okta":
		return "okta", nil
	case "authentik":
		return "authentik", nil
	case "pocketid":
		return "pocketid", nil
	case "auth0":
		// Auth0 uses generic OIDC in Dex (no named connector)
		return "oidc", nil
	case "azure":
		return "entra", nil
	case "google":
		return "google", nil
	case "jumpcloud":
		return "", fmt.Errorf("jumpcloud does not have a supported Dex connector type")
	default:
		// Generic OIDC fallback
		return "oidc", nil
	}
}

// generateConfig reads the existing management.json as raw JSON, removes
// IdpManagerConfig, adds EmbeddedIdP, updates HttpConfig fields, and writes
// the result. In dry-run mode, it prints the new config to stdout instead.
func generateConfig(configPath string, conn *dex.Connector, cfg *nbconfig.Config, dryRun bool) error {
	domain, err := deriveDomain(cfg)
	if err != nil {
		return fmt.Errorf("derive domain: %w", err)
	}
	log.Infof("derived domain for embedded IdP: %s", domain)

	// Read existing config as raw JSON to preserve all fields
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(raw, &configMap); err != nil {
		return fmt.Errorf("parse config JSON: %w", err)
	}

	// Remove old IdP config
	delete(configMap, "IdpManagerConfig")

	// Add EmbeddedIdP section
	configMap["EmbeddedIdP"] = map[string]interface{}{
		"Enabled":               true,
		"Issuer":                fmt.Sprintf("https://%s/oauth2", domain),
		"SignKeyRefreshEnabled": true,
		"LocalAuthDisabled":     true,
		"DashboardRedirectURIs": []string{
			fmt.Sprintf("https://%s/nb-auth", domain),
			fmt.Sprintf("https://%s/nb-silent-auth", domain),
		},
		"CLIRedirectURIs": []string{
			"http://localhost:53000/",
			"http://localhost:54000/",
		},
		"StaticConnectors": []interface{}{
			map[string]interface{}{
				"type":   conn.Type,
				"name":   conn.Name,
				"id":     conn.ID,
				"config": conn.Config,
			},
		},
	}

	// Update HttpConfig fields
	httpConfig, _ := configMap["HttpConfig"].(map[string]interface{})
	if httpConfig == nil {
		httpConfig = map[string]interface{}{}
		configMap["HttpConfig"] = httpConfig
	}
	httpConfig["AuthIssuer"] = fmt.Sprintf("https://%s/oauth2", domain)
	httpConfig["AuthKeysLocation"] = fmt.Sprintf("https://%s/oauth2/keys", domain)
	httpConfig["OIDCConfigEndpoint"] = fmt.Sprintf("https://%s/oauth2/.well-known/openid-configuration", domain)
	httpConfig["AuthClientID"] = "netbird-dashboard"
	if _, ok := httpConfig["AuthUserIDClaim"]; !ok {
		httpConfig["AuthUserIDClaim"] = "sub"
	}

	newJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal new config: %w", err)
	}

	if dryRun {
		log.Info("[DRY RUN] new management.json would be:")
		fmt.Println(string(newJSON))
		return nil
	}

	// Backup original
	backupPath := configPath + ".bak"
	if err := os.WriteFile(backupPath, raw, 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	log.Infof("backed up original config to %s", backupPath)

	// Write new config
	if err := os.WriteFile(configPath, newJSON, 0600); err != nil {
		return fmt.Errorf("write new config: %w", err)
	}
	log.Infof("wrote new config to %s", configPath)

	return nil
}

// deriveDomain determines the management server domain from existing config,
// using a priority-based approach.
func deriveDomain(cfg *nbconfig.Config) (string, error) {
	// Priority 1: LetsEncryptDomain (most explicit)
	if cfg.HttpConfig != nil && cfg.HttpConfig.LetsEncryptDomain != "" {
		return cfg.HttpConfig.LetsEncryptDomain, nil
	}

	// Priority 2: parse from OIDCConfigEndpoint
	if cfg.HttpConfig != nil && cfg.HttpConfig.OIDCConfigEndpoint != "" {
		if host := hostFromURL(cfg.HttpConfig.OIDCConfigEndpoint); host != "" {
			return host, nil
		}
	}

	// Priority 3: parse from AuthIssuer
	if cfg.HttpConfig != nil && cfg.HttpConfig.AuthIssuer != "" {
		if host := hostFromURL(cfg.HttpConfig.AuthIssuer); host != "" {
			return host, nil
		}
	}

	// Priority 4: parse from IdpManagerConfig.ClientConfig.Issuer
	if cfg.IdpManagerConfig != nil && cfg.IdpManagerConfig.ClientConfig != nil && cfg.IdpManagerConfig.ClientConfig.Issuer != "" {
		if host := hostFromURL(cfg.IdpManagerConfig.ClientConfig.Issuer); host != "" {
			return host, nil
		}
	}

	return "", fmt.Errorf("could not determine domain: set HttpConfig.LetsEncryptDomain, HttpConfig.AuthIssuer, or HttpConfig.OIDCConfigEndpoint in management.json")
}

// hostFromURL extracts the host (without port) from a URL string.
func hostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Compile-time check that migrationServer implements migration.Server.
var _ migration.Server = (*migrationServer)(nil)
