package store

// This file contains migration-only methods on SqlStore.
// They satisfy the migration.Store interface via duck typing.
// Delete this file when migration tooling is no longer needed.

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/idp/migration"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) CheckSchema(checks []migration.SchemaCheck) []migration.SchemaError {
	migrator := s.db.Migrator()
	var errs []migration.SchemaError

	for _, check := range checks {
		if !migrator.HasTable(check.Table) {
			errs = append(errs, migration.SchemaError{Table: check.Table})
			continue
		}
		for _, col := range check.Columns {
			if !migrator.HasColumn(check.Table, col) {
				errs = append(errs, migration.SchemaError{Table: check.Table, Column: col})
			}
		}
	}

	return errs
}

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
	if s.storeEngine == types.SqliteStoreEngine {
		return tx.Exec("PRAGMA defer_foreign_keys = ON").Error
	}

	if s.storeEngine != types.PostgresStoreEngine {
		return nil
	}

	// GORM creates FK constraints as NOT DEFERRABLE by default, so
	// SET CONSTRAINTS ALL DEFERRED is a no-op unless we ALTER them first.
	err := tx.Exec(`
			DO $$ DECLARE r RECORD;
			BEGIN
				FOR r IN SELECT conname, conrelid::regclass AS tbl
				         FROM pg_constraint WHERE contype = 'f' AND NOT condeferrable
				LOOP
					EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I DEFERRABLE INITIALLY IMMEDIATE', r.tbl, r.conname);
				END LOOP;
			END $$
		`).Error
	if err != nil {
		return fmt.Errorf("make FK constraints deferrable: %w", err)
	}
	return tx.Exec("SET CONSTRAINTS ALL DEFERRED").Error
}

// txRestoreFKConstraints reverts FK constraints back to NOT DEFERRABLE after the
// deferred updates are done but before the transaction commits.
func (s *SqlStore) txRestoreFKConstraints(tx *gorm.DB) error {
	if s.storeEngine != types.PostgresStoreEngine {
		return nil
	}

	return tx.Exec(`
		DO $$ DECLARE r RECORD;
		BEGIN
			FOR r IN SELECT conname, conrelid::regclass AS tbl
			         FROM pg_constraint WHERE contype = 'f' AND condeferrable
			LOOP
				EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I NOT DEFERRABLE', r.tbl, r.conname);
			END LOOP;
		END $$
	`).Error
}

func (s *SqlStore) UpdateUserInfo(ctx context.Context, userID, email, name string) error {
	user := &types.User{Email: email, Name: name}
	if err := user.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt user info: %w", err)
	}

	result := s.db.Model(&types.User{}).Where("id = ?", userID).Updates(map[string]any{
		"email": user.Email,
		"name":  user.Name,
	})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error updating user info for %s: %s", userID, result.Error)
		return status.Errorf(status.Internal, "failed to update user info")
	}

	return nil
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

	log.Info("Updating user ID in the store")
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

	log.Info("Restoring FK constraints")
	err = s.transaction(func(tx *gorm.DB) error {
		if err := s.txRestoreFKConstraints(tx); err != nil {
			return fmt.Errorf("restore FK constraints: %w", err)
		}

		return nil
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to restore FK constraints after user ID update: %s", err)
		return status.Errorf(status.Internal, "failed to restore FK constraints after user ID update")
	}

	return nil
}
