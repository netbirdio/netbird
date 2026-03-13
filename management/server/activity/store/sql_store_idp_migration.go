package store

// This file contains migration-only methods on Store.
// They satisfy the migration.MigrationEventStore interface via duck typing.
// Delete this file when migration tooling is no longer needed.

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/activity"
)

// UpdateUserID updates all references to oldUserID in events and deleted_users tables.
func (store *Store) UpdateUserID(ctx context.Context, oldUserID, newUserID string) error {
	return store.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&activity.Event{}).
			Where("initiator_id = ?", oldUserID).
			Update("initiator_id", newUserID).Error; err != nil {
			return fmt.Errorf("update events.initiator_id: %w", err)
		}

		if err := tx.Model(&activity.Event{}).
			Where("target_id = ?", oldUserID).
			Update("target_id", newUserID).Error; err != nil {
			return fmt.Errorf("update events.target_id: %w", err)
		}

		// Raw exec: GORM can't update a PK via Model().Update()
		if err := tx.Exec(
			"UPDATE deleted_users SET id = ? WHERE id = ?", newUserID, oldUserID,
		).Error; err != nil {
			return fmt.Errorf("update deleted_users.id: %w", err)
		}

		return nil
	})
}
