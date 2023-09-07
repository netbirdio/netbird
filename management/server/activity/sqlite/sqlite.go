package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	// sqlite driver
	_ "github.com/mattn/go-sqlite3"
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

	selectStatement = `SELECT events.id, activity, timestamp, initiator_id, i.email as "initiator_email", target_id, t.email as "target_email", account_id, meta
    	FROM events 
    	LEFT JOIN deleted_users i ON events.initiator_id = i.id 
    	LEFT JOIN deleted_users t ON events.target_id = t.id
		WHERE account_id = ? 
		ORDER BY timestamp %s LIMIT ? OFFSET ?;`
	insertStatement = "INSERT INTO events(activity, timestamp, initiator_id, target_id, account_id, meta) " +
		"VALUES(?, ?, ?, ?, ?, ?)"

	insertDeleteUserStatement = `INSERT INTO deleted_users(id, email) VALUES(?, ?)`
)

// Store is the implementation of the activity.Store interface backed by SQLite
type Store struct {
	db           *sql.DB
	emailEncrypt *EmailEncrypt
}

// NewSQLiteStore creates a new Store with an event table if not exists.
func NewSQLiteStore(dataDir string, encryptionKey string) (*Store, error) {
	dbFile := filepath.Join(dataDir, eventSinkDB)
	db, err := sql.Open("sqlite3", dbFile)
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

	crypt, err := NewEmailEncrypt(encryptionKey)
	if err != nil {
		return nil, err
	}

	s := &Store{
		db:           db,
		emailEncrypt: crypt,
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
				log.Errorf("failed to decrypt data: %s", *targetEmail)
				meta["email"] = ""
			} else {
				meta["email"] = email
			}
		}

		if initiatorEmail != nil {
			email, err := store.emailEncrypt.Decrypt(*initiatorEmail)
			if err != nil {
				log.Errorf("failed to decrypt data: %s", *initiatorEmail)
				*initiatorEmail = ""
			} else {
				*initiatorEmail = email
			}
		}

		events = append(events, &activity.Event{
			Timestamp:      timestamp,
			Activity:       operation,
			ID:             uint64(id),
			InitiatorID:    initiator,
			InitiatorEmail: initiatorEmail,
			TargetID:       target,
			AccountID:      account,
			Meta:           meta,
		})
	}

	return events, nil
}

// Get returns "limit" number of events from index ordered descending or ascending by a timestamp
func (store *Store) Get(accountID string, offset, limit int, descending bool) ([]*activity.Event, error) {
	order := "DESC"
	if !descending {
		order = "ASC"
	}
	stmt, err := store.db.Prepare(fmt.Sprintf(selectStatement, order))
	if err != nil {
		return nil, err
	}

	result, err := stmt.Query(accountID, limit, offset)
	if err != nil {
		return nil, err
	}

	defer result.Close() //nolint
	return store.processResult(result)
}

// Save an event in the SQLite events table
func (store *Store) Save(event *activity.Event) (*activity.Event, error) {
	stmt, err := store.db.Prepare(insertStatement)
	if err != nil {
		return nil, err
	}

	var jsonMeta string
	if event.Meta != nil {
		metaBytes, err := json.Marshal(event.Meta)
		if err != nil {
			return nil, err
		}
		jsonMeta = string(metaBytes)
	}

	result, err := stmt.Exec(event.Activity, event.Timestamp, event.InitiatorID, event.TargetID, event.AccountID, jsonMeta)
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

func (store *Store) SaveWithDeletedUserEmail(event *activity.Event, email string) (*activity.Event, error) {
	email = store.emailEncrypt.Encrypt(email)

	stmt, err := store.db.Prepare(insertDeleteUserStatement)
	if err != nil {
		return nil, err
	}

	_, err = stmt.Exec(event.TargetID, email)
	if err != nil {
		return nil, err
	}

	return store.Save(event)
}

// Close the Store
func (store *Store) Close() error {
	if store.db != nil {
		return store.db.Close()
	}
	return nil
}
