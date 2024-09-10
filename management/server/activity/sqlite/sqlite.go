package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
)

const (
	// eventSinkDB is the default name of the events database
	eventSinkDB      = "events.db"
	createTableQuery = "CREATE TABLE IF NOT EXISTS events " +
		"(id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"activity INTEGER, " +
		"timestamp DATETIME, " +
		"initiator_id TEXT," +
		"account_id TEXT," +
		"meta TEXT," +
		" target_id TEXT);"

	creatTableDeletedUsersQuery = `CREATE TABLE IF NOT EXISTS deleted_users (id TEXT NOT NULL, email TEXT NOT NULL, name TEXT, enc_algo TEXT NOT NULL);`

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

	insertQuery = "INSERT INTO events(activity, timestamp, initiator_id, target_id, account_id, meta) " +
		"VALUES(?, ?, ?, ?, ?, ?)"

	/*
		 TODO:
			The insert should avoid duplicated IDs in the table. So the query should be changes to something like:
			`INSERT INTO deleted_users(id, email, name) VALUES(?, ?, ?) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name;`
			For this to work we have to set the id column as primary key. But this is not possible because the id column is not unique
			and some selfhosted deployments might have duplicates already so we need to clean the table first.
	*/

	insertDeleteUserQuery = `INSERT INTO deleted_users(id, email, name, enc_algo) VALUES(?, ?, ?, ?)`

	fallbackName  = "unknown"
	fallbackEmail = "unknown@unknown.com"

	gcmEncAlgo = "GCM"
)

// Store is the implementation of the activity.Store interface backed by SQLite
type Store struct {
	db           *sql.DB
	fieldEncrypt *FieldEncrypt

	insertStatement     *sql.Stmt
	selectAscStatement  *sql.Stmt
	selectDescStatement *sql.Stmt
	deleteUserStmt      *sql.Stmt
}

// NewSQLiteStore creates a new Store with an event table if not exists.
func NewSQLiteStore(ctx context.Context, dataDir string, encryptionKey string) (*Store, error) {
	dbFile := filepath.Join(dataDir, eventSinkDB)
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}

	crypt, err := NewFieldEncrypt(encryptionKey)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	if err = migrate(ctx, crypt, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("events database migration: %w", err)
	}

	return createStore(crypt, db)
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
	var jsonMeta string
	meta, err := store.saveDeletedUserEmailAndNameInEncrypted(event)
	if err != nil {
		return nil, err
	}

	if meta != nil {
		metaBytes, err := json.Marshal(event.Meta)
		if err != nil {
			return nil, err
		}
		jsonMeta = string(metaBytes)
	}

	result, err := store.insertStatement.Exec(event.Activity, event.Timestamp, event.InitiatorID, event.TargetID, event.AccountID, jsonMeta)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	eventCopy := event.Copy()
	eventCopy.ID = uint64(id)
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

	encryptedEmail, err := store.fieldEncrypt.Encrypt(fmt.Sprintf("%s", email))
	if err != nil {
		return nil, err
	}
	encryptedName, err := store.fieldEncrypt.Encrypt(fmt.Sprintf("%s", name))
	if err != nil {
		return nil, err
	}

	_, err = store.deleteUserStmt.Exec(event.TargetID, encryptedEmail, encryptedName, gcmEncAlgo)
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
	if store.db != nil {
		return store.db.Close()
	}
	return nil
}

// createStore initializes and returns a new Store instance with prepared SQL statements.
func createStore(crypt *FieldEncrypt, db *sql.DB) (*Store, error) {
	insertStmt, err := db.Prepare(insertQuery)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	selectDescStmt, err := db.Prepare(selectDescQuery)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	selectAscStmt, err := db.Prepare(selectAscQuery)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	deleteUserStmt, err := db.Prepare(insertDeleteUserQuery)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{
		db:                  db,
		fieldEncrypt:        crypt,
		insertStatement:     insertStmt,
		selectDescStatement: selectDescStmt,
		selectAscStatement:  selectAscStmt,
		deleteUserStmt:      deleteUserStmt,
	}, nil
}

// checkColumnExists checks if a column exists in a specified table
func checkColumnExists(db *sql.DB, tableName, columnName string) (bool, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s);", tableName)
	rows, err := db.Query(query)
	if err != nil {
		return false, fmt.Errorf("failed to query table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue sql.NullString

		err = rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if err != nil {
			return false, fmt.Errorf("failed to scan row: %w", err)
		}

		if name == columnName {
			return true, nil
		}
	}

	if err = rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}
