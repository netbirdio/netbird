package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func migrate(ctx context.Context, crypt *FieldEncrypt, db *sql.DB) error {
	if err := updateDeletedUsersTable(ctx, db); err != nil {
		return fmt.Errorf("failed to update deleted_users table: %v", err)
	}

	return migrateLegacyEncryptedUsersToGCM(ctx, crypt, db)
}

// updateDeletedUsersTable checks and updates the deleted_users table schema to ensure required columns exist.
func updateDeletedUsersTable(ctx context.Context, db *sql.DB) error {
	exists, err := checkColumnExists(db, "deleted_users", "name")
	if err != nil {
		return err
	}

	if !exists {
		log.WithContext(ctx).Debug("Adding name column to the deleted_users table")

		_, err = db.Exec(`ALTER TABLE deleted_users ADD COLUMN name TEXT;`)
		if err != nil {
			return err
		}

		log.WithContext(ctx).Debug("Successfully added name column to the deleted_users table")
	}

	exists, err = checkColumnExists(db, "deleted_users", "enc_algo")
	if err != nil {
		return err
	}

	if !exists {
		log.WithContext(ctx).Debug("Adding enc_algo column to the deleted_users table")

		_, err = db.Exec(`ALTER TABLE deleted_users ADD COLUMN enc_algo TEXT;`)
		if err != nil {
			return err
		}

		log.WithContext(ctx).Debug("Successfully added enc_algo column to the deleted_users table")
	}

	return nil
}

// migrateLegacyEncryptedUsersToGCM migrates previously encrypted data using,
// legacy CBC encryption with a static IV to the new GCM encryption method.
func migrateLegacyEncryptedUsersToGCM(ctx context.Context, crypt *FieldEncrypt, db *sql.DB) error {
	log.WithContext(ctx).Debug("Migrating CBC encrypted deleted users to GCM")

	rows, err := db.Query(fmt.Sprintf(`SELECT id, email, name FROM deleted_users where enc_algo != '%s'`, gcmEncAlgo))
	if err != nil {
		return fmt.Errorf("failed to execute select query: %v", err)
	}
	defer rows.Close()

	updateStmt, err := db.Prepare(`UPDATE deleted_users SET email = ?, name = ?, enc_algo = ? WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare update statement: %v", err)
	}
	defer updateStmt.Close()

	if err = processUserRows(ctx, crypt, rows, updateStmt); err != nil {
		return err
	}

	log.WithContext(ctx).Debug("Successfully migrated CBC encrypted deleted users to GCM")
	return nil
}

// processUserRows processes database rows of user data, decrypts legacy encryption fields, and re-encrypts them using GCM.
func processUserRows(ctx context.Context, crypt *FieldEncrypt, rows *sql.Rows, updateStmt *sql.Stmt) error {
	for rows.Next() {
		var id int
		var email, name string

		if err := rows.Scan(&id, &email, &name); err != nil {
			return err
		}

		decryptedEmail, err := crypt.LegacyDecrypt(email)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to decrypt email for deleted user: %d", id)
			email = fallbackEmail
		}

		decryptedName, err := crypt.LegacyDecrypt(name)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to decrypt name for deleted user: %d", id)
			name = fallbackName
		}

		encryptedEmail, err := crypt.Encrypt(decryptedEmail)
		if err != nil {
			return fmt.Errorf("failed to encrypt email for deleted user: %d", id)
		}

		encryptedName, err := crypt.Encrypt(decryptedName)
		if err != nil {
			return fmt.Errorf("failed to encrypt name for deleted user: %d", id)
		}

		_, err = updateStmt.Exec(encryptedEmail, encryptedName, gcmEncAlgo, id)
		if err != nil {
			return err
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return nil
}