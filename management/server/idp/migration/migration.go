// Package migration provides utility functions for migrating from the external IdP solution in pre v0.62.0
// to the new embedded IdP manager (Dex based), which is the default in v0.62.0 and later.
// It includes functions to seed connectors and migrate existing users to use these connectors.
package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/types"
)

// Server is the dependency interface that migration functions use to access
// the main data store and the activity event store.
type Server interface {
	Store() Store
	EventStore() EventStore // may return nil
}

const idpSeedInfoKey = "IDP_SEED_INFO"
const dryRunEnvKey = "NB_IDP_MIGRATION_DRY_RUN"

func isDryRun() bool {
	return os.Getenv(dryRunEnvKey) == "true"
}

var ErrNoSeedInfo = errors.New("no seed info found in environment")

// SeedConnectorFromEnv reads the IDP_SEED_INFO env var, base64-decodes it,
// and JSON-unmarshals it into a dex.Connector. Returns nil if not set.
func SeedConnectorFromEnv() (*dex.Connector, error) {
	val, ok := os.LookupEnv(idpSeedInfoKey)
	if !ok || val == "" {
		return nil, ErrNoSeedInfo
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
func reconcileActivityStore(ctx context.Context, eventStore EventStore, users []*types.User) error {
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

// PopulateUserInfo fetches user email and name from the external IDP and updates
// the store for users that are missing this information.
func PopulateUserInfo(s Server, idpManager idp.Manager, dryRun bool) error {
	ctx := context.Background()

	users, err := s.Store().ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	// Build a map of IDP user ID -> UserData from the external IDP
	allAccounts, err := idpManager.GetAllAccounts(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch accounts from IDP: %w", err)
	}

	idpUsers := make(map[string]*idp.UserData)
	for _, accountUsers := range allAccounts {
		for _, userData := range accountUsers {
			idpUsers[userData.ID] = userData
		}
	}

	log.Infof("fetched %d users from IDP", len(idpUsers))

	var updatedCount, skippedCount, notFoundCount int

	for _, user := range users {
		if user.IsServiceUser {
			skippedCount++
			continue
		}

		if user.Email != "" && user.Name != "" {
			skippedCount++
			continue
		}

		// The user ID in the store may be the original IDP ID or a Dex-encoded ID.
		// Try to decode the Dex format first to get the original IDP ID.
		lookupID := user.Id
		if originalID, _, decErr := dex.DecodeDexUserID(user.Id); decErr == nil {
			lookupID = originalID
		}

		idpUser, found := idpUsers[lookupID]
		if !found {
			notFoundCount++
			log.Debugf("user %s (lookup: %s) not found in IDP, skipping", user.Id, lookupID)
			continue
		}

		email := user.Email
		name := user.Name
		if email == "" && idpUser.Email != "" {
			email = idpUser.Email
		}
		if name == "" && idpUser.Name != "" {
			name = idpUser.Name
		}

		if email == user.Email && name == user.Name {
			skippedCount++
			continue
		}

		if dryRun {
			log.Infof("[DRY RUN] would update user %s: email=%q, name=%q", user.Id, email, name)
			updatedCount++
			continue
		}

		if err := s.Store().UpdateUserInfo(ctx, user.Id, email, name); err != nil {
			return fmt.Errorf("failed to update user info for %s: %w", user.Id, err)
		}

		log.Infof("updated user %s: email=%q, name=%q", user.Id, email, name)
		updatedCount++
	}

	if dryRun {
		log.Infof("[DRY RUN] user info summary: %d would be updated, %d skipped, %d not found in IDP", updatedCount, skippedCount, notFoundCount)
	} else {
		log.Infof("user info population complete: %d updated, %d skipped, %d not found in IDP", updatedCount, skippedCount, notFoundCount)
	}

	return nil
}
