package sqlite

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/migration"
)

func migrate(ctx context.Context, crypt *FieldEncrypt, db *gorm.DB) error {
	migrations := getMigrations(ctx, crypt)

	for _, m := range migrations {
		if err := m(db); err != nil {
			return err
		}
	}

	return nil
}

type migrationFunc func(*gorm.DB) error

func getMigrations(ctx context.Context, crypt *FieldEncrypt) []migrationFunc {
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
		// TODO: Migrate All deleted users to remove duplicates and add the id as primary key
	}
}

// migrateLegacyEncryptedUsersToGCM migrates previously encrypted data using
// legacy CBC encryption with a static IV to the new GCM encryption method.
func migrateLegacyEncryptedUsersToGCM(ctx context.Context, db *gorm.DB, crypt *FieldEncrypt) error {
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
			if err = migrateDeletedUser(tx, user, crypt); err != nil {
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

func migrateDeletedUser(transaction *gorm.DB, user activity.DeletedUser, crypt *FieldEncrypt) error {
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

	return transaction.Model(&user).Where("id = ?", updatedUser.ID).Updates(updatedUser).Error
}
