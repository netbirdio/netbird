// Package migration provides utility functions for migrating from the external IdP solution in pre v0.60.0
// to the new embedded IdP manager (Dex based), which is the default in v0.60.0 and later.
// It includes functions to seed connectors and migrate existing users to use these connectors.
package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// Server is the dependency interface that migration functions use to access
// the main data store and the activity event store.
type Server interface {
	Store() store.Store
	EventStore() activity.Store
}

const idpSeedInfoKey = "IDP_SEED_INFO"
const dryRunEnvKey = "NB_IDP_MIGRATION_DRY_RUN"

// IsSeedInfoPresent reports whether the IDP_SEED_INFO environment variable is
// set to a non-empty value, indicating that connector seed information is available.
func IsSeedInfoPresent() bool {
	val, ok := os.LookupEnv(idpSeedInfoKey)
	return ok && val != ""
}

func isDryRun() bool {
	return os.Getenv(dryRunEnvKey) == "true"
}

// SeedConnectorFromEnv reads the IDP_SEED_INFO env var, base64-decodes it,
// and JSON-unmarshals it into a dex.Connector. Returns nil if not set.
func SeedConnectorFromEnv() (*dex.Connector, error) {
	val, ok := os.LookupEnv(idpSeedInfoKey)
	if !ok || val == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var conn dex.Connector
	if err := json.Unmarshal(decoded, &conn); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	return &conn, nil
}

// MigrateUsersToStaticConnectors re-keys every user ID in the main store (and
// the activity store, if present) so that it encodes the given connector ID,
// skipping users that have already been migrated. Set NB_IDP_MIGRATION_DRY_RUN=true
// to log what would happen without writing any changes.
func MigrateUsersToStaticConnectors(s Server, conn *dex.Connector) error {
	ctx := context.Background()

	if isDryRun() {
		log.Info("[DRY RUN] migration dry-run mode enabled, no changes will be written")
	}

	users, err := s.Store().ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	// Reconciliation pass: fix activity store for users already migrated in main DB
	// but whose activity references may still use old IDs (from a previous partial failure).
	if s.EventStore() != nil && !isDryRun() {
		if err := reconcileActivityStore(ctx, s.EventStore(), users); err != nil {
			return err
		}
	}

	var migratedCount, skippedCount int

	for _, user := range users {
		_, _, decErr := dex.DecodeDexUserID(user.Id)
		if decErr == nil {
			skippedCount++
			continue
		}

		newUserID := dex.EncodeDexUserID(user.Id, conn.ID)

		if isDryRun() {
			log.Infof("[DRY RUN] would migrate user %s -> %s (account: %s)", user.Id, newUserID, user.AccountID)
			migratedCount++
			continue
		}

		if err := migrateUser(ctx, s, user.Id, user.AccountID, newUserID); err != nil {
			return err
		}

		migratedCount++
	}

	if isDryRun() {
		log.Infof("[DRY RUN] migration summary: %d users would be migrated, %d already migrated", migratedCount, skippedCount)
	} else {
		log.Infof("migration complete: %d users migrated, %d already migrated", migratedCount, skippedCount)
	}

	return nil
}

// reconcileActivityStore updates activity store references for users already migrated
// in the main DB whose activity entries may still use old IDs from a previous partial failure.
func reconcileActivityStore(ctx context.Context, eventStore activity.Store, users []*types.User) error {
	for _, user := range users {
		originalID, _, err := dex.DecodeDexUserID(user.Id)
		if err != nil {
			// skip users that aren't migrated, they will be handled in the main migration loop
			continue
		}
		if err := eventStore.UpdateUserID(ctx, originalID, user.Id); err != nil {
			return fmt.Errorf("reconcile activity store for user %s: %w", user.Id, err)
		}
	}
	return nil
}

// migrateUser updates a single user's ID in both the main store and the activity store.
func migrateUser(ctx context.Context, s Server, oldID, accountID, newID string) error {
	if err := s.Store().UpdateUserID(ctx, accountID, oldID, newID); err != nil {
		return fmt.Errorf("failed to update user ID for user %s: %w", oldID, err)
	}

	if s.EventStore() == nil {
		return nil
	}

	if err := s.EventStore().UpdateUserID(ctx, oldID, newID); err != nil {
		return fmt.Errorf("failed to update activity store user ID for user %s: %w", oldID, err)
	}

	return nil
}
