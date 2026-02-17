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
	"github.com/netbirdio/netbird/management/server/store"
)

type Server interface {
	Store() store.Store
}

const idpSeedInfoKey = "IDP_SEED_INFO"
const dryRunEnvKey = "NB_IDP_MIGRATION_DRY_RUN"

func IsSeedInfoPresent() bool {
	val, ok := os.LookupEnv(idpSeedInfoKey)
	return ok && val != ""
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

func MigrateUsersToStaticConnectors(s Server, conn *dex.Connector) error {
	ctx := context.Background()
	dryRun := os.Getenv(dryRunEnvKey) == "true"

	if dryRun {
		log.Info("[DRY RUN] migration dry-run mode enabled, no changes will be written")
	}

	users, err := s.Store().ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	var migratedCount, skippedCount int

	for _, user := range users {
		_, _, decErr := dex.DecodeDexUserID(user.Id)
		if decErr == nil {
			skippedCount++
			continue
		}

		newUserID := dex.EncodeDexUserID(user.Id, conn.ID)

		if dryRun {
			log.Infof("[DRY RUN] would migrate user %s -> %s (account: %s)", user.Id, newUserID, user.AccountID)
			migratedCount++
			continue
		}

		if err := s.Store().UpdateUserID(ctx, user.AccountID, user.Id, newUserID); err != nil {
			return fmt.Errorf("failed to update user ID for user %s: %w", user.Id, err)
		}

		migratedCount++
	}

	if dryRun {
		log.Infof("[DRY RUN] migration summary: %d users would be migrated, %d already migrated", migratedCount, skippedCount)
	} else {
		log.Infof("migration complete: %d users migrated, %d already migrated", migratedCount, skippedCount)
	}

	return nil
}
