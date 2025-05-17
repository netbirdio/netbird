package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/server/activity"
)

const (
	// eventSinkDB is the default name of the events database
	eventSinkDB   = "events.db"
	fallbackName  = "unknown"
	fallbackEmail = "unknown@unknown.com"
	gcmEncAlgo    = "GCM"

	selectDescQuery = `SELECT events.id, activity, timestamp, initiator_id, i.name as "initiator_name", i.email as "initiator_email", target_id, t.name as "target_name", t.email as "target_email", account_id, meta
		FROM events 
		LEFT JOIN (
		    SELECT id, MAX(name) as name, MAX(email) as email 
		    FROM deleted_users
		    GROUP BY id
		) i ON events.initiator_id = i.id 
		LEFT JOIN (
		    SELECT id, MAX(name) as name, MAX(email) as email 
		    FROM deleted_users
		    GROUP BY id
		) t ON events.target_id = t.id
		WHERE account_id = ? 
		ORDER BY timestamp DESC LIMIT ? OFFSET ?;`

	selectAscQuery = `SELECT events.id, activity, timestamp, initiator_id, i.name as "initiator_name", i.email as "initiator_email", target_id, t.name as "target_name", t.email as "target_email", account_id, meta
		FROM events 
		LEFT JOIN (
		    SELECT id, MAX(name) as name, MAX(email) as email 
		    FROM deleted_users
		    GROUP BY id
		) i ON events.initiator_id = i.id 
		LEFT JOIN (
		    SELECT id, MAX(name) as name, MAX(email) as email 
		    FROM deleted_users
		    GROUP BY id
		) t ON events.target_id = t.id
		WHERE account_id = ? 
		ORDER BY timestamp ASC LIMIT ? OFFSET ?;`
)

// Store is the implementation of the activity.Store interface backed by SQLite
type Store struct {
	oldDb        *sql.DB
	db           *gorm.DB
	fieldEncrypt *FieldEncrypt

	selectAscStatement  *sql.Stmt
	selectDescStatement *sql.Stmt
}

// NewSQLiteStore creates a new Store with an event table if not exists.
func NewSQLiteStore(ctx context.Context, dataDir string, encryptionKey string) (*Store, error) {
	crypt, err := NewFieldEncrypt(encryptionKey)
	if err != nil {

		return nil, err
	}

	dbFile := filepath.Join(dataDir, eventSinkDB)
	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	sql.SetMaxOpenConns(1)

	if err = migrate(ctx, crypt, db); err != nil {
		return nil, fmt.Errorf("events database migration: %w", err)
	}

	err = db.AutoMigrate(&activity.Event{}, &activity.DeletedUser{})
	if err != nil {
		return nil, fmt.Errorf("events auto migrate: %w", err)
	}

	return createStore(crypt, db, sql)
}

func (store *Store) processResult(ctx context.Context, result *sql.Rows) ([]*activity.Event, error) {
	events := make([]*activity.Event, 0)
	var cryptErr error
	for result.Next() {
		var id int64
		var operation activity.Activity
		var timestamp time.Time
		var initiator string
		var initiatorName *string
		var initiatorEmail *string
		var target string
		var targetUserName *string
		var targetEmail *string
		var account string
		var jsonMeta string
		err := result.Scan(&id, &operation, &timestamp, &initiator, &initiatorName, &initiatorEmail, &target, &targetUserName, &targetEmail, &account, &jsonMeta)
		if err != nil {
			return nil, err
		}

		meta := make(map[string]any)
		if jsonMeta != "" {
			err = json.Unmarshal([]byte(jsonMeta), &meta)
			if err != nil {
				return nil, err
			}
		}

		if targetUserName != nil {
			name, err := store.fieldEncrypt.Decrypt(*targetUserName)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt username for target id: %s", target)
				meta["username"] = fallbackName
			} else {
				meta["username"] = name
			}
		}

		if targetEmail != nil {
			email, err := store.fieldEncrypt.Decrypt(*targetEmail)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt email address for target id: %s", target)
				meta["email"] = fallbackEmail
			} else {
				meta["email"] = email
			}
		}

		event := &activity.Event{
			Timestamp:   timestamp,
			Activity:    operation,
			ID:          uint64(id),
			InitiatorID: initiator,
			TargetID:    target,
			AccountID:   account,
			Meta:        meta,
		}

		if initiatorName != nil {
			name, err := store.fieldEncrypt.Decrypt(*initiatorName)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt username of initiator: %s", initiator)
				event.InitiatorName = fallbackName
			} else {
				event.InitiatorName = name
			}
		}

		if initiatorEmail != nil {
			email, err := store.fieldEncrypt.Decrypt(*initiatorEmail)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt email address of initiator: %s", initiator)
				event.InitiatorEmail = fallbackEmail
			} else {
				event.InitiatorEmail = email
			}
		}

		events = append(events, event)
	}

	if cryptErr != nil {
		log.WithContext(ctx).Warnf("%s", cryptErr)
	}

	return events, nil
}

// Get returns "limit" number of events from index ordered descending or ascending by a timestamp
func (store *Store) Get(ctx context.Context, accountID string, offset, limit int, descending bool) ([]*activity.Event, error) {
	stmt := store.selectDescStatement
	if !descending {
		stmt = store.selectAscStatement
	}

	result, err := stmt.Query(accountID, limit, offset)
	if err != nil {
		return nil, err
	}

	defer result.Close() //nolint
	return store.processResult(ctx, result)
}

// Save an event in the SQLite events table end encrypt the "email" element in meta map
func (store *Store) Save(_ context.Context, event *activity.Event) (*activity.Event, error) {
	eventCopy := event.Copy()
	meta, err := store.saveDeletedUserEmailAndNameInEncrypted(eventCopy)
	if err != nil {
		return nil, err
	}
	eventCopy.Meta = meta

	if err = store.db.Create(eventCopy).Error; err != nil {
		return nil, err
	}

	return eventCopy, nil
}

// saveDeletedUserEmailAndNameInEncrypted if the meta contains email and name then store it in encrypted way and delete
// this item from meta map
func (store *Store) saveDeletedUserEmailAndNameInEncrypted(event *activity.Event) (map[string]any, error) {
	email, ok := event.Meta["email"]
	if !ok {
		return event.Meta, nil
	}

	name, ok := event.Meta["name"]
	if !ok {
		return event.Meta, nil
	}

	deletedUser := activity.DeletedUser{
		ID:      event.TargetID,
		EncAlgo: gcmEncAlgo,
	}

	encryptedEmail, err := store.fieldEncrypt.Encrypt(fmt.Sprintf("%s", email))
	if err != nil {
		return nil, err
	}
	deletedUser.Email = encryptedEmail

	encryptedName, err := store.fieldEncrypt.Encrypt(fmt.Sprintf("%s", name))
	if err != nil {
		return nil, err
	}
	deletedUser.Name = encryptedName

	err = store.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"email", "name"}),
	}).Create(deletedUser).Error
	if err != nil {
		return nil, err
	}

	if len(event.Meta) == 2 {
		return nil, nil // nolint
	}
	delete(event.Meta, "email")
	delete(event.Meta, "name")
	return event.Meta, nil
}

// Close the Store
func (store *Store) Close(_ context.Context) error {
	if store.oldDb != nil {
		return store.oldDb.Close()
	}
	return nil
}

// createStore initializes and returns a new Store instance with prepared SQL statements.
func createStore(crypt *FieldEncrypt, db *gorm.DB, sql *sql.DB) (*Store, error) {
	selectDescStmt, err := sql.Prepare(selectDescQuery)
	if err != nil {
		_ = sql.Close()
		return nil, err
	}

	selectAscStmt, err := sql.Prepare(selectAscQuery)
	if err != nil {
		_ = sql.Close()
		return nil, err
	}

	return &Store{
		oldDb:               sql,
		db:                  db,
		fieldEncrypt:        crypt,
		selectDescStatement: selectDescStmt,
		selectAscStatement:  selectAscStmt,
	}, nil
}
