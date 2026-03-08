// Command migrate-idp is a standalone CLI tool that migrates self-hosted NetBird
// deployments from an external IdP (Zitadel, Keycloak, Okta, etc.) to NetBird's
// embedded DEX-based IdP. It re-keys all user IDs in the database to match DEX's
// encoded format.
//
// Usage:
//
//	migrate-idp --config /etc/netbird/management.json --connector-id oidc [--dry-run]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/management/server/idp/migration"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"
)

func main() {
	configPath := flag.String("config", "/etc/netbird/management.json", "path to management.json config file")
	connectorID := flag.String("connector-id", "", "DEX connector ID to encode into user IDs (required)")
	dryRun := flag.Bool("dry-run", false, "preview changes without writing to the database")
	noBackup := flag.Bool("no-backup", false, "skip automatic database backup (SQLite only)")
	logLevel := flag.String("log-level", "info", "log verbosity: debug, info, warn, error")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `migrate-idp - Migrate NetBird user IDs from external IdP to embedded DEX

This tool re-keys all user IDs in the management database so they match DEX's
encoded format (base64-encoded protobuf with user ID + connector ID). Run this
with management stopped, then update management.json to enable EmbeddedIdP.

Service users (IsServiceUser=true) are re-keyed like all other users. All user
types will be looked up by DEX-encoded IDs after migration.

Usage:
  migrate-idp --config /etc/netbird/management.json --connector-id oidc [flags]

Flags:
`)
		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, `
Migration procedure:
  1. Stop management:   systemctl stop netbird-management
  2. Dry-run:           migrate-idp --config <path> --connector-id <id> --dry-run
  3. Run migration:     migrate-idp --config <path> --connector-id <id>
  4. Update management.json: Add EmbeddedIdP config with matching connector ID
  5. Start management:  systemctl start netbird-management
`)
	}

	flag.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("invalid log level %q: %v", *logLevel, err)
	}
	log.SetLevel(level)

	if *connectorID == "" {
		fmt.Fprintln(os.Stderr, "error: --connector-id is required")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(context.Background(), *configPath, *connectorID, *dryRun, *noBackup); err != nil {
		log.Fatalf("migration failed: %v", err)
	}
}

func run(ctx context.Context, configPath, connectorID string, dryRun, noBackup bool) error {
	// Load management config
	config := &nbconfig.Config{}
	if _, err := util.ReadJsonWithEnvSub(configPath, config); err != nil {
		return fmt.Errorf("read config %s: %w", configPath, err)
	}

	if config.Datadir == "" {
		return fmt.Errorf("config has empty Datadir")
	}

	log.Infof("loaded config from %s (datadir: %s, engine: %s)", configPath, config.Datadir, config.StoreConfig.Engine)

	if dryRun {
		log.Info("[DRY RUN] mode enabled — no changes will be written")
	}

	// Open main store
	mainStore, err := store.NewStore(ctx, config.StoreConfig.Engine, config.Datadir, nil, false)
	if err != nil {
		return fmt.Errorf("open main store: %w", err)
	}
	defer mainStore.Close(ctx) //nolint:errcheck

	// Set up field encryption for user data decryption
	if config.DataStoreEncryptionKey != "" {
		fieldEncrypt, err := crypt.NewFieldEncrypt(config.DataStoreEncryptionKey)
		if err != nil {
			return fmt.Errorf("create field encryptor: %w", err)
		}
		mainStore.SetFieldEncrypt(fieldEncrypt)
	}

	// Open activity store (optional — warn and continue if unavailable)
	var actStore migration.ActivityStoreUpdater
	activitySqlStore, err := activitystore.NewSqlStore(ctx, config.Datadir, config.DataStoreEncryptionKey)
	if err != nil {
		log.Warnf("could not open activity store, activity events will not be migrated: %v", err)
	} else {
		defer activitySqlStore.Close(ctx) //nolint:errcheck
		actStore = activitySqlStore
	}

	// Backup databases before migration (unless --no-backup or --dry-run)
	if !noBackup && !dryRun {
		if err := backupDatabases(config.Datadir, config.StoreConfig.Engine); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}

	// Run migration
	result, err := migration.Migrate(ctx, &migration.Config{
		ConnectorID:   connectorID,
		DryRun:        dryRun,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\nMigration summary:\n")
	fmt.Printf("  Migrated: %d users\n", result.Migrated)
	fmt.Printf("  Skipped:  %d users (already migrated)\n", result.Skipped)
	if dryRun {
		fmt.Printf("\n  [DRY RUN] No changes were written. Remove --dry-run to apply.\n")
	} else if result.Migrated > 0 {
		fmt.Printf("\n  Next step: update management.json to enable EmbeddedIdP with connector ID %q\n", connectorID)
	}

	return nil
}
