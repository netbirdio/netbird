package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3" // sqlite driver
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
)

const (
	//eventSinkDB is the default name of the events database
	eventSinkDB      = "events.db"
	createTableQuery = "CREATE TABLE IF NOT EXISTS events " +
		"(id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"activity INTEGER, " +
		"timestamp DATETIME, " +
		"initiator_id TEXT," +
		"account_id TEXT," +
		"meta TEXT," +
		" target_id TEXT);"

	creatTableAccountEmailQuery = `CREATE TABLE IF NOT EXISTS deleted_users (id TEXT NOT NULL, email TEXT NOT NULL);`

	selectDescQuery = `SELECT events.id, activity, timestamp, initiator_id, i.email as "initiator_email", target_id, t.email as "target_email", account_id, meta
    	FROM events 
    	LEFT JOIN deleted_users i ON events.initiator_id = i.id 
    	LEFT JOIN deleted_users t ON events.target_id = t.id
		WHERE account_id = ? 
		ORDER BY timestamp DESC LIMIT ? OFFSET ?;`

	selectAscQuery = `SELECT events.id, activity, timestamp, initiator_id, i.email as "initiator_email", target_id, t.email as "target_email", account_id, meta
    	FROM events 
    	LEFT JOIN deleted_users i ON events.initiator_id = i.id 
    	LEFT JOIN deleted_users t ON events.target_id = t.id
		WHERE account_id = ? 
		ORDER BY timestamp ASC LIMIT ? OFFSET ?;`

	insertQuery = "INSERT INTO events(activity, timestamp, initiator_id, target_id, account_id, meta) " +
		"VALUES(?, ?, ?, ?, ?, ?)"

	insertDeleteUserQuery = `INSERT INTO deleted_users(id, email) VALUES(?, ?)`
)

// Store is the implementation of the activity.Store interface backed by SQLite
type Store struct {
	db           *sql.DB
	emailEncrypt *EmailEncrypt

	insertStatement     *sql.Stmt
	selectAscStatement  *sql.Stmt
	selectDescStatement *sql.Stmt
	deleteUserStmt      *sql.Stmt
}

// NewSQLiteStore creates a new Store with an event table if not exists.
func NewSQLiteStore(dataDir string, encryptionKey string) (*Store, error) {
	dbFile := filepath.Join(dataDir, eventSinkDB)
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}

	crypt, err := NewEmailEncrypt(encryptionKey)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(creatTableAccountEmailQuery)
	if err != nil {
		return nil, err
	}

	insertStmt, err := db.Prepare(insertQuery)
	if err != nil {
		return nil, err
	}

	selectDescStmt, err := db.Prepare(selectDescQuery)
	if err != nil {
		return nil, err
	}

	selectAscStmt, err := db.Prepare(selectAscQuery)
	if err != nil {
		return nil, err
	}

	deleteUserStmt, err := db.Prepare(insertDeleteUserQuery)
	if err != nil {
		return nil, err
	}

	s := &Store{
		db:                  db,
		emailEncrypt:        crypt,
		insertStatement:     insertStmt,
		selectDescStatement: selectDescStmt,
		selectAscStatement:  selectAscStmt,
		deleteUserStmt:      deleteUserStmt,
	}
	return s, nil
}

func (store *Store) processResult(result *sql.Rows) ([]*activity.Event, error) {
	events := make([]*activity.Event, 0)
	for result.Next() {
		var id int64
		var operation activity.Activity
		var timestamp time.Time
		var initiator string
		var initiatorEmail *string
		var target string
		var targetEmail *string
		var account string
		var jsonMeta string
		err := result.Scan(&id, &operation, &timestamp, &initiator, &initiatorEmail, &target, &targetEmail, &account, &jsonMeta)
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

		if targetEmail != nil {
			email, err := store.emailEncrypt.Decrypt(*targetEmail)
			if err != nil {
				log.Errorf("failed to decrypt email address for target id: %s", target)
				meta["email"] = ""
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

		if initiatorEmail != nil {
			email, err := store.emailEncrypt.Decrypt(*initiatorEmail)
			if err != nil {
				log.Errorf("failed to decrypt email address of initiator: %s", initiator)
			} else {
				event.InitiatorEmail = email
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// Get returns "limit" number of events from index ordered descending or ascending by a timestamp
func (store *Store) Get(accountID string, offset, limit int, descending bool) ([]*activity.Event, error) {
	stmt := store.selectDescStatement
	if !descending {
		stmt = store.selectAscStatement
	}

	result, err := stmt.Query(accountID, limit, offset)
	if err != nil {
		return nil, err
	}

	defer result.Close() //nolint
	return store.processResult(result)
}

// Save an event in the SQLite events table end encrypt the "email" element in meta map
func (store *Store) Save(event *activity.Event) (*activity.Event, error) {
	var jsonMeta string
	meta, err := store.saveDeletedUserEmailInEncrypted(event)
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

// saveDeletedUserEmailInEncrypted if the meta contains email then store it in encrypted way and delete this item from
// meta map
func (store *Store) saveDeletedUserEmailInEncrypted(event *activity.Event) (map[string]any, error) {
	email, ok := event.Meta["email"]
	if !ok {
		return event.Meta, nil
	}

	delete(event.Meta, "email")

	encrypted := store.emailEncrypt.Encrypt(fmt.Sprintf("%s", email))
	_, err := store.deleteUserStmt.Exec(event.TargetID, encrypted)
	if err != nil {
		return nil, err
	}

	if len(event.Meta) == 1 {
		return nil, nil // nolint
	}
	delete(event.Meta, "email")
	return event.Meta, nil
}

// Close the Store
func (store *Store) Close() error {
	if store.db != nil {
		return store.db.Close()
	}
	return nil
}
