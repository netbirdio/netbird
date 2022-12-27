package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/management/server/activity"

	// sqlite driver
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
	"time"
)

const (
	//SQLiteEventSinkDB is the default name of the events database
	SQLiteEventSinkDB = "events.db"
	createTableQuery  = "CREATE TABLE IF NOT EXISTS events " +
		"(id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"activity INTEGER, " +
		"timestamp DATETIME, " +
		"initiator_id TEXT," +
		"account_id TEXT," +
		"meta TEXT," +
		" target_id TEXT);"
)

// SQLiteStore is the implementation of the activity.Store interface backed by SQLite
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLiteStore with an event table if not exists.
func NewSQLiteStore(dataDir string) (*SQLiteStore, error) {
	dbFile := filepath.Join(dataDir, SQLiteEventSinkDB)
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func processResult(result *sql.Rows) ([]*activity.Event, error) {
	events := make([]*activity.Event, 0)
	for result.Next() {
		var id int64
		var operation activity.Activity
		var timestamp time.Time
		var initiator string
		var target string
		var account string
		var jsonMeta string
		err := result.Scan(&id, &operation, &timestamp, &initiator, &target, &account, &jsonMeta)
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

		events = append(events, &activity.Event{
			Timestamp:   timestamp,
			Activity:    operation,
			ID:          uint64(id),
			InitiatorID: initiator,
			TargetID:    target,
			AccountID:   account,
			Meta:        meta,
		})
	}

	return events, nil
}

// Get returns "limit" number of events from index ordered descending or ascending by a timestamp
func (store *SQLiteStore) Get(accountID string, offset, limit int, descending bool) ([]*activity.Event, error) {
	order := "DESC"
	if !descending {
		order = "ASC"
	}
	stmt, err := store.db.Prepare(fmt.Sprintf("SELECT id, activity, timestamp, initiator_id, target_id, account_id, meta"+
		" FROM events WHERE account_id = ? ORDER BY timestamp %s LIMIT ? OFFSET ?;", order))
	if err != nil {
		return nil, err
	}

	result, err := stmt.Query(accountID, limit, offset)
	if err != nil {
		return nil, err
	}

	defer result.Close() //nolint
	return processResult(result)
}

// Save an event in the SQLite events table
func (store *SQLiteStore) Save(event *activity.Event) (*activity.Event, error) {

	stmt, err := store.db.Prepare("INSERT INTO events(activity, timestamp, initiator_id, target_id, account_id, meta) VALUES(?, ?, ?, ?, ?, ?)")
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

// Close the SQLiteStore
func (store *SQLiteStore) Close() error {
	if store.db != nil {
		return store.db.Close()
	}
	return nil
}
