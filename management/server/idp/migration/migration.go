// Package migration provides utility functions for migrating from an external IdP
// to NetBird's embedded DEX-based IdP. It re-keys user IDs in the main store and
// activity store so that they match DEX's encoded format.
package migration

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/types"
)

// MainStoreUpdater is the subset of the main store needed for migration.
type MainStoreUpdater interface {
	ListUsers(ctx context.Context) ([]*types.User, error)
	UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
}

// ActivityStoreUpdater is the subset of the activity store needed for migration.
type ActivityStoreUpdater interface {
	UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
}

// Config holds migration parameters.
type Config struct {
	ConnectorID   string
	DryRun        bool
	MainStore     MainStoreUpdater
	ActivityStore ActivityStoreUpdater // nil if activity store is unavailable
}

// Result holds migration outcome counts.
type Result struct {
	Migrated int
	Skipped  int
}

// progressInterval controls how often progress is logged for large user counts.
const progressInterval = 100

// Migrate re-keys every user ID in both stores so that it encodes the given
// connector ID. Already-migrated users (detectable via DecodeDexUserID) are
// skipped, making the operation idempotent.
func Migrate(ctx context.Context, cfg *Config) (*Result, error) {
	if cfg.ConnectorID == "" {
		return nil, fmt.Errorf("connector ID must not be empty")
	}

	users, err := cfg.MainStore.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	if len(users) == 0 {
		log.Info("no users found, nothing to migrate")
		return &Result{}, nil
	}

	log.Infof("found %d users to process", len(users))

	// Reconciliation pass: fix activity store for users already migrated in
	// the main DB but whose activity references may still use old IDs (from
	// a previous partial failure).
	if cfg.ActivityStore != nil && !cfg.DryRun {
		if err := reconcileActivityStore(ctx, cfg.ActivityStore, users); err != nil {
			return nil, err
		}
	}

	res := &Result{}

	for i, user := range users {
		if user.Id == "" {
			log.Warnf("skipping user with empty ID in account %s", user.AccountID)
			res.Skipped++
			continue
		}

		_, _, decErr := dex.DecodeDexUserID(user.Id)
		if decErr == nil {
			// Already encoded in DEX format — skip.
			res.Skipped++
			continue
		}

		newUserID := dex.EncodeDexUserID(user.Id, cfg.ConnectorID)

		if cfg.DryRun {
			log.Infof("[DRY RUN] would migrate user %s -> %s (account: %s)",
				user.Id, newUserID, user.AccountID)
			res.Migrated++
			continue
		}

		if err := migrateUser(ctx, cfg, user.Id, user.AccountID, newUserID); err != nil {
			return nil, err
		}

		res.Migrated++

		if (i+1)%progressInterval == 0 {
			log.Infof("progress: %d/%d users processed", i+1, len(users))
		}
	}

	if cfg.DryRun {
		log.Infof("[DRY RUN] migration summary: %d users would be migrated, %d already migrated",
			res.Migrated, res.Skipped)
	} else {
		log.Infof("migration complete: %d users migrated, %d already migrated",
			res.Migrated, res.Skipped)
	}

	return res, nil
}

// reconcileActivityStore updates activity store references for users already
// migrated in the main DB whose activity entries may still use old IDs from a
// previous partial failure.
func reconcileActivityStore(ctx context.Context, activityStore ActivityStoreUpdater, users []*types.User) error {
	for _, user := range users {
		originalID, _, err := dex.DecodeDexUserID(user.Id)
		if err != nil {
			// Not yet migrated — will be handled in the main loop.
			continue
		}
		if err := activityStore.UpdateUserID(ctx, originalID, user.Id); err != nil {
			return fmt.Errorf("reconcile activity store for user %s: %w", user.Id, err)
		}
	}
	return nil
}

// migrateUser updates a single user's ID in both the main store and the activity store.
func migrateUser(ctx context.Context, cfg *Config, oldID, accountID, newID string) error {
	if err := cfg.MainStore.UpdateUserID(ctx, accountID, oldID, newID); err != nil {
		return fmt.Errorf("update user ID for user %s: %w", oldID, err)
	}

	if cfg.ActivityStore == nil {
		return nil
	}

	if err := cfg.ActivityStore.UpdateUserID(ctx, oldID, newID); err != nil {
		return fmt.Errorf("update activity store user ID for user %s: %w", oldID, err)
	}

	return nil
}
