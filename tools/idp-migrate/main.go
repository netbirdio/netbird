// Package main provides a standalone CLI tool to migrate user IDs from an
// external IdP format to the embedded Dex IdP format used by NetBird >= v0.62.0.
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
	"fmt"
	"maps"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/idp/migration"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"
)

// migrationServer implements migration.Server by wrapping the migration-specific interfaces.
type migrationServer struct {
	store      migration.Store
	eventStore migration.EventStore
}

func (s *migrationServer) Store() migration.Store           { return s.store }
func (s *migrationServer) EventStore() migration.EventStore { return s.eventStore }

func main() {
	cfg, err := config()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	if !cfg.dryRun {
		printPostMigrationInstructions(cfg)
	}
}

func run(cfg *migrationConfig) error {
	mgmtConfig := &nbconfig.Config{}
	if _, err := util.ReadJsonWithEnvSub(cfg.configPath, mgmtConfig); err != nil {
		return err
	}

	// Validate the database schema before attempting any operations.
	if err := validateSchema(mgmtConfig, cfg.dataDir); err != nil {
		return err
	}

	if !cfg.skipPopulateUserInfo {
		err := populateUserInfoFromIDP(cfg, mgmtConfig)
		if err != nil {
			return fmt.Errorf("populate user info: %w", err)
		}
	}

	connectorConfig, err := decodeConnectorConfig(cfg.idpSeedInfo)
	if err != nil {
		return fmt.Errorf("resolve connector: %w", err)
	}

	log.Infof(
		"resolved connector: type=%s, id=%s, name=%s",
		connectorConfig.Type,
		connectorConfig.ID,
		connectorConfig.Name,
	)

	if err := migrateDB(cfg, mgmtConfig, connectorConfig); err != nil {
		return err
	}

	if cfg.skipConfig {
		log.Info("skipping config generation (--skip-config)")
		return nil
	}

	return generateConfig(cfg, connectorConfig)
}

// validateSchema opens the store and checks that all required tables and columns
// exist. If anything is missing, it returns a descriptive error telling the user
// to upgrade their management server.
func validateSchema(mgmtConfig *nbconfig.Config, dataDir string) error {
	ctx := context.Background()
	migStore, migEventStore, cleanup, err := openStores(ctx, mgmtConfig, dataDir)
	if err != nil {
		return err
	}
	defer cleanup()

	errs := migStore.CheckSchema(migration.RequiredSchema)
	if len(errs) > 0 {
		return fmt.Errorf("%s", formatSchemaErrors(errs))
	}

	if migEventStore != nil {
		eventErrs := migEventStore.CheckSchema(migration.RequiredEventSchema)
		if len(eventErrs) > 0 {
			return fmt.Errorf("activity store schema check failed (upgrade management server first):\n%s", formatSchemaErrors(eventErrs))
		}
	}

	log.Info("database schema check passed")
	return nil
}

// formatSchemaErrors returns a user-friendly message listing all missing schema
// elements and instructing the operator to upgrade.
func formatSchemaErrors(errs []migration.SchemaError) string {
	var b strings.Builder
	b.WriteString("database schema is incomplete — the following tables/columns are missing:\n")
	for _, e := range errs {
		fmt.Fprintf(&b, "  - %s\n", e.String())
	}
	b.WriteString("\nPlease start the NetBird management server (v0.66.4+) at least once so that automatic database migrations create the required schema, then re-run this tool.\n")
	return b.String()
}

// populateUserInfoFromIDP creates an IDP manager from the config, fetches all
// user data (email, name) from the external IDP, and updates the store for users
// that are missing this information.
func populateUserInfoFromIDP(cfg *migrationConfig, mgmtConfig *nbconfig.Config) error {
	ctx := context.Background()

	if mgmtConfig.IdpManagerConfig == nil {
		return fmt.Errorf("IdpManagerConfig is not set in management.json; cannot fetch user info from IDP")
	}

	idpManager, err := idp.NewManager(ctx, *mgmtConfig.IdpManagerConfig, nil)
	if err != nil {
		return fmt.Errorf("create IDP manager: %w", err)
	}
	if idpManager == nil {
		return fmt.Errorf("IDP manager type is 'none' or empty; cannot fetch user info")
	}

	log.Infof("created IDP manager (type: %s)", mgmtConfig.IdpManagerConfig.ManagerType)

	migStore, _, cleanup, err := openStores(ctx, mgmtConfig, cfg.dataDir)
	if err != nil {
		return err
	}
	defer cleanup()

	srv := &migrationServer{store: migStore}
	return migration.PopulateUserInfo(srv, idpManager, cfg.dryRun)
}

// openStores opens the main and activity stores, returning migration-specific interfaces.
// The caller must call the returned cleanup function to close the stores.
func openStores(ctx context.Context, cfg *nbconfig.Config, dataDir string) (migration.Store, migration.EventStore, func(), error) {
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

	migStore, ok := mainStore.(migration.Store)
	if !ok {
		_ = mainStore.Close(ctx)
		return nil, nil, nil, fmt.Errorf("store does not support migration operations (ListUsers/UpdateUserID)")
	}

	cleanup := func() { _ = mainStore.Close(ctx) }

	var migEventStore migration.EventStore
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
func migrateDB(cfg *migrationConfig, mgmtConfig *nbconfig.Config, connectorConfig *dex.Connector) error {
	ctx := context.Background()

	migStore, migEventStore, cleanup, err := openStores(ctx, mgmtConfig, cfg.dataDir)
	if err != nil {
		return err
	}
	defer cleanup()

	pending, err := previewUsers(ctx, migStore)
	if err != nil {
		return err
	}

	if cfg.dryRun {
		if err := os.Setenv("NB_IDP_MIGRATION_DRY_RUN", "true"); err != nil {
			return fmt.Errorf("set dry-run env: %w", err)
		}
		defer os.Unsetenv("NB_IDP_MIGRATION_DRY_RUN") //nolint:errcheck
	}

	if !cfg.dryRun && !cfg.force {
		if !confirmPrompt(pending) {
			log.Info("migration cancelled by user")
			return nil
		}
	}

	srv := &migrationServer{store: migStore, eventStore: migEventStore}
	if err := migration.MigrateUsersToStaticConnectors(srv, connectorConfig); err != nil {
		return fmt.Errorf("migrate users: %w", err)
	}

	if !cfg.dryRun {
		log.Info("DB migration completed successfully")
	}
	return nil
}

// previewUsers counts pending vs already-migrated users and logs a summary.
// Returns the number of users still needing migration.
func previewUsers(ctx context.Context, migStore migration.Store) (int, error) {
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
	log.Infof("About to migrate %d users. This cannot be easily undone. Continue? [y/N] ", pending)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

// decodeConnectorConfig base64-decodes and JSON-unmarshals a connector.
func decodeConnectorConfig(encoded string) (*dex.Connector, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var conn dex.Connector
	if err := json.Unmarshal(decoded, &conn); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	if conn.ID == "" {
		return nil, fmt.Errorf("connector ID is empty")
	}

	return &conn, nil
}

// generateConfig reads the existing management.json as raw JSON, removes
// IdpManagerConfig, adds EmbeddedIdP, updates HttpConfig fields, and writes
// the result. In dry-run mode, it prints the new config to stdout instead.
func generateConfig(cfg *migrationConfig, connectorConfig *dex.Connector) error {
	// Read existing config as raw JSON to preserve all fields
	raw, err := os.ReadFile(cfg.configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var configMap map[string]any
	if err := json.Unmarshal(raw, &configMap); err != nil {
		return fmt.Errorf("parse config JSON: %w", err)
	}

	// Remove unused information
	delete(configMap, "IdpManagerConfig")
	delete(configMap, "PKCEAuthorizationFlow")
	delete(configMap, "DeviceAuthorizationFlow")

	httpConfig, ok := configMap["HttpConfig"].(map[string]any)
	if httpConfig != nil && ok {
		certFilePath := httpConfig["CertFile"]
		certKeyPath := httpConfig["CertKey"]

		delete(configMap, "HttpConfig")

		configMap["HttpConfig"] = map[string]any{
			"CertFile": certFilePath,
			"CertKey":  certKeyPath,
		}
	}

	// Ensure the connector's redirectURI points to the management server (Dex callback),
	// not the external IdP. The auto-detection may have used the IdP issuer URL.
	connConfig := make(map[string]any, len(connectorConfig.Config))
	maps.Copy(connConfig, connectorConfig.Config)

	redirectURI, err := buildURL(cfg.apiURL, "/oauth2/callback")
	if err != nil {
		return fmt.Errorf("build redirect URI: %w", err)
	}
	connConfig["redirectURI"] = redirectURI

	issuer, err := buildURL(cfg.apiURL, "/oauth2")
	if err != nil {
		return fmt.Errorf("build issuer URL: %w", err)
	}

	dashboardRedirectURL, err := buildURL(cfg.dashboardURL, "/nb-auth")
	if err != nil {
		return fmt.Errorf("build dashboard redirect URL: %w", err)
	}

	dashboardSilentRedirectURL, err := buildURL(cfg.dashboardURL, "/nb-silent-auth")
	if err != nil {
		return fmt.Errorf("build dashboard silent redirect URL: %w", err)
	}

	// Add minimal EmbeddedIdP section
	configMap["EmbeddedIdP"] = map[string]any{
		"Enabled": true,
		"Issuer":  issuer,
		"DashboardRedirectURIs": []string{
			dashboardRedirectURL,
			dashboardSilentRedirectURL,
		},
		"StaticConnectors": []any{
			map[string]any{
				"type":   connectorConfig.Type,
				"name":   connectorConfig.Name,
				"id":     connectorConfig.ID,
				"config": connConfig,
			},
		},
	}

	newJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal new config: %w", err)
	}

	if cfg.dryRun {
		log.Info("[DRY RUN] new management.json would be:")
		log.Infoln(string(newJSON))
		return nil
	}

	// Backup original
	backupPath := cfg.configPath + ".bak"
	if err := os.WriteFile(backupPath, raw, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	log.Infof("backed up original config to %s", backupPath)

	// Write new config
	if err := os.WriteFile(cfg.configPath, newJSON, 0o600); err != nil {
		return fmt.Errorf("write new config: %w", err)
	}
	log.Infof("wrote new config to %s", cfg.configPath)

	return nil
}

func buildURL(uri, path string) (string, error) {
	// Case for domain without scheme, e.g. "example.com" or "example.com:8080"
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		uri = "https://" + uri
	}

	val, err := url.JoinPath(uri, path)
	if err != nil {
		return "", err
	}

	return val, nil
}

func printPostMigrationInstructions(cfg *migrationConfig) {
	authAuthority, err := buildURL(cfg.apiURL, "/oauth2")
	if err != nil {
		authAuthority = "https://<your-domain>/oauth2"
	}

	log.Info("Congratulations! You have successfully migrated your NetBird management server to the embedded Dex IdP.")
	log.Info("Next steps:")
	log.Info("1. Make sure the following environment variables are set for your dashboard server:")
	log.Infof(`
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_AUTHORITY=%s
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
	`,
		authAuthority,
	)
	log.Info("2. Make sure you restart the dashboard & management servers to pick up the new config and environment variables.")
	log.Info("eg. docker compose up -d --force-recreate management dashboard")
	log.Info("3. Optional: If you have a reverse proxy configured, make sure the path `/oauth2/*` points to the management api server.")
}

// Compile-time check that migrationServer implements migration.Server.
var _ migration.Server = (*migrationServer)(nil)
