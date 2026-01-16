package store

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/migration"
	"github.com/netbirdio/netbird/util/crypt"
)

func migrate(ctx context.Context, crypt *crypt.FieldEncrypt, db *gorm.DB) error {
	migrations := getMigrations(ctx, crypt)

	for _, m := range migrations {
		if err := m(db); err != nil {
			return err
		}
	}

	return nil
}

type migrationFunc func(*gorm.DB) error

func getMigrations(ctx context.Context, crypt *crypt.FieldEncrypt) []migrationFunc {
	return []migrationFunc{
		func(db *gorm.DB) error {
			return migration.MigrateNewField[activity.DeletedUser](ctx, db, "name", "")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNewField[activity.DeletedUser](ctx, db, "enc_algo", "")
		},
		func(db *gorm.DB) error {
			return migrateLegacyEncryptedUsersToGCM(ctx, db, crypt)
		},
		func(db *gorm.DB) error {
			return migrateDuplicateDeletedUsers(ctx, db)
		},
	}
}

// migrateLegacyEncryptedUsersToGCM migrates previously encrypted data using
// legacy CBC encryption with a static IV to the new GCM encryption method.
func migrateLegacyEncryptedUsersToGCM(ctx context.Context, db *gorm.DB, crypt *crypt.FieldEncrypt) error {
	model := &activity.DeletedUser{}

	if !db.Migrator().HasTable(model) {
		log.WithContext(ctx).Debugf("Table for %T does not exist, no CBC to GCM migration needed", model)
		return nil
	}

	var deletedUsers []activity.DeletedUser
	err := db.Model(model).Find(&deletedUsers, "enc_algo IS NULL OR enc_algo != ?", gcmEncAlgo).Error
	if err != nil {
		return fmt.Errorf("failed to query deleted_users: %w", err)
	}

	if len(deletedUsers) == 0 {
		log.WithContext(ctx).Debug("No CBC encrypted deleted users to migrate")
		return nil
	}

	if err = db.Transaction(func(tx *gorm.DB) error {
		for _, user := range deletedUsers {
			if err = updateDeletedUserData(tx, user, crypt); err != nil {
				return fmt.Errorf("failed to migrate deleted user %s: %w", user.ID, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	log.WithContext(ctx).Debug("Successfully migrated CBC encrypted deleted users to GCM")

	return nil
}

func updateDeletedUserData(transaction *gorm.DB, user activity.DeletedUser, crypt *crypt.FieldEncrypt) error {
	var err error
	var decryptedEmail, decryptedName string

	if user.Email != "" {
		decryptedEmail, err = crypt.LegacyDecrypt(user.Email)
		if err != nil {
			return fmt.Errorf("failed to decrypt email: %w", err)
		}
	}

	if user.Name != "" {
		decryptedName, err = crypt.LegacyDecrypt(user.Name)
		if err != nil {
			return fmt.Errorf("failed to decrypt name: %w", err)
		}
	}

	updatedUser := user
	updatedUser.EncAlgo = gcmEncAlgo

	updatedUser.Email, err = crypt.Encrypt(decryptedEmail)
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}

	updatedUser.Name, err = crypt.Encrypt(decryptedName)
	if err != nil {
		return fmt.Errorf("failed to encrypt name: %w", err)
	}

	return transaction.Model(&updatedUser).Omit("id").Updates(updatedUser).Error
}

// MigrateDuplicateDeletedUsers removes duplicates and ensures the id column is marked as the primary key
func migrateDuplicateDeletedUsers(ctx context.Context, db *gorm.DB) error {
	model := &activity.DeletedUser{}
	if !db.Migrator().HasTable(model) {
		log.WithContext(ctx).Debugf("Table for %T does not exist, no duplicate migration needed", model)
		return nil
	}

	isPrimaryKey, err := isColumnPrimaryKey[activity.DeletedUser](db, "id")
	if err != nil {
		return err
	}

	if isPrimaryKey {
		log.WithContext(ctx).Debug("No duplicate deleted users to migrate")
		return nil
	}

	if err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Migrator().RenameTable("deleted_users", "deleted_users_old"); err != nil {
			return err
		}

		if err = tx.Migrator().CreateTable(model); err != nil {
			return err
		}

		var deletedUsers []activity.DeletedUser
		if err = tx.Table("deleted_users_old").Find(&deletedUsers).Error; err != nil {
			return err
		}

		for _, deletedUser := range deletedUsers {
			if err = tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns([]string{"email", "name", "enc_algo"}),
			}).Create(&deletedUser).Error; err != nil {
				return err
			}
		}

		return tx.Migrator().DropTable("deleted_users_old")
	}); err != nil {
		return err
	}

	log.WithContext(ctx).Debug("Successfully migrated duplicate deleted users")

	return nil
}

// isColumnPrimaryKey checks if a column is a primary key in the given model
func isColumnPrimaryKey[T any](db *gorm.DB, columnName string) (bool, error) {
	var model T

	cols, err := db.Migrator().ColumnTypes(&model)
	if err != nil {
		return false, err
	}

	for _, col := range cols {
		if col.Name() == columnName {
			isPrimaryKey, _ := col.PrimaryKey()
			return isPrimaryKey, nil
		}
	}

	return false, nil
}
