package store

// This file contains migration-only methods on SqlStore.
// They satisfy the migration.MigrationStore interface via duck typing.
// Delete this file when migration tooling is no longer needed.

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/management/server/types"
)

func (s *SqlStore) ListUsers(ctx context.Context) ([]*types.User, error) {
	tx := s.db
	var users []*types.User
	result := tx.Find(&users)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when listing users from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue listing users from store")
	}

	for _, user := range users {
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
		}
	}

	return users, nil
}

// txDeferFKConstraints defers foreign key constraint checks for the duration of the transaction.
// MySQL is already handled by s.transaction (SET FOREIGN_KEY_CHECKS = 0).
func (s *SqlStore) txDeferFKConstraints(tx *gorm.DB) error {
	switch s.storeEngine {
	case types.PostgresStoreEngine:
		return tx.Exec("SET CONSTRAINTS ALL DEFERRED").Error
	case types.SqliteStoreEngine:
		return tx.Exec("PRAGMA defer_foreign_keys = ON").Error
	default:
		return nil
	}
}

func (s *SqlStore) UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error {
	type fkUpdate struct {
		model  any
		column string
		where  string
	}

	updates := []fkUpdate{
		{&types.PersonalAccessToken{}, "user_id", "user_id = ?"},
		{&types.PersonalAccessToken{}, "created_by", "created_by = ?"},
		{&nbpeer.Peer{}, "user_id", "user_id = ?"},
		{&types.UserInviteRecord{}, "created_by", "created_by = ?"},
		{&types.Account{}, "created_by", "created_by = ?"},
		{&types.ProxyAccessToken{}, "created_by", "created_by = ?"},
		{&types.Job{}, "triggered_by", "triggered_by = ?"},
	}

	err := s.transaction(func(tx *gorm.DB) error {
		if err := s.txDeferFKConstraints(tx); err != nil {
			return err
		}

		for _, u := range updates {
			if err := tx.Model(u.model).Where(u.where, oldUserID).Update(u.column, newUserID).Error; err != nil {
				return fmt.Errorf("update %s: %w", u.column, err)
			}
		}

		if err := tx.Model(&types.User{}).Where(accountAndIDQueryCondition, accountID, oldUserID).Update("id", newUserID).Error; err != nil {
			return fmt.Errorf("update users: %w", err)
		}

		return nil
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to update user ID in the store: %s", err)
		return status.Errorf(status.Internal, "failed to update user ID in store")
	}

	return nil
}
