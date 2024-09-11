package sqlite

import (
	"database/sql"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func (store *Store) GetLegacyEvents() error {
	rows, err := store.db.Query(`SELECT id, email, name FROM deleted_users`)
	if err != nil {
		return fmt.Errorf("failed to execute select query: %v", err)
	}
	defer rows.Close()

	if err = processLegacyEvents(store.fieldEncrypt, rows); err != nil {
		return err
	}

	return nil
}

// processUserRows processes database rows of user data, decrypts legacy encryption fields, and re-encrypts them using GCM.
func processLegacyEvents(crypt *FieldEncrypt, rows *sql.Rows) error {
	var (
		successCount int
		failureCount int
	)

	for rows.Next() {
		var (
			id          string
			email, name *string
		)

		err := rows.Scan(&id, &email, &name)
		if err != nil {
			return err
		}

		if email != nil {
			_, err = crypt.LegacyDecrypt(*email)
			if err != nil {
				log.Warnf("failed to decrypt email for user %s: %v",
					id,
					fmt.Errorf("failed to decrypt email: %w", err),
				)
				failureCount++
				continue
			}
		}

		if name != nil {
			_, err = crypt.LegacyDecrypt(*name)
			if err != nil {
				log.Warnf("failed to decrypt name for user %s: %v",
					id,
					fmt.Errorf("failed to decrypt name: %w", err),
				)
				failureCount++
				continue
			}
		}

		successCount++

	}

	if err := rows.Err(); err != nil {
		return err
	}

	log.Infof("Successfully decoded entries: %d", successCount)
	log.Infof("Failed decoded entries: %d", failureCount)

	return nil
}
