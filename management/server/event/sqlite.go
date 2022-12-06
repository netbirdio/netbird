package event

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
	"time"
)

const (
	SQLiteEventSinkDB = "events.db"
	createTableQuery  = "CREATE TABLE IF NOT EXISTS events " +
		"(id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, " +
		"operation TEXT, " +
		"type TEXT, " +
		"timestamp DATETIME, " +
		"modifier TEXT," +
		" target TEXT);"
)

// SQLiteStore is the implementation of the event.Store interface backed by SQLite
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

func processResult(result *sql.Rows) ([]Event, error) {
	events := make([]Event, 0)
	for result.Next() {
		var id int64
		var operation string
		var timestamp time.Time
		var modifier string
		var target string
		var account string
		var typ Type
		err := result.Scan(&id, &operation, &timestamp, &modifier, &target, &account, &typ)
		if err != nil {
			return nil, err
		}

		events = append(events, Event{
			Timestamp:  timestamp,
			Operation:  operation,
			ID:         uint64(id),
			Type:       typ,
			ModifierID: modifier,
			TargetID:   target,
			AccountID:  account,
		})
	}

	return events, nil
}

// GetLast returns a top N of events from the store for a given account (ordered by timestamp desc)
func (store *SQLiteStore) GetLast(accountID string, limit int) ([]Event, error) {
	stmt, err := store.db.Prepare("SELECT id, operation, timestamp, modifier, target, account, type" +
		" FROM events WHERE account = ? ORDER BY timestamp DESC limit ?;")
	if err != nil {
		return nil, err
	}

	result, err := stmt.Query(accountID, limit)
	if err != nil {
		return nil, err
	}

	defer result.Close() //nolint
	return processResult(result)
}

// GetSince returns a list of events from the store for a given account since the specified time
func (store *SQLiteStore) GetSince(accountID string, from time.Time) ([]Event, error) {
	stmt, err := store.db.Prepare("SELECT id, operation, timestamp, modifier, target, account, type" +
		" FROM events WHERE account = ? and timestamp >= ?;")
	if err != nil {
		return nil, err
	}

	result, err := stmt.Query(accountID, from)
	if err != nil {
		return nil, err
	}

	defer result.Close() //nolint
	return processResult(result)
}

// Save an event in the SQLite events table
func (store *SQLiteStore) Save(event Event) (*Event, error) {

	stmt, err := store.db.Prepare("INSERT INTO events(operation, timestamp, modifier, target, account, type) VALUES(?, ?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}

	result, err := stmt.Exec(event.Operation, event.Timestamp, event.ModifierID, event.TargetID, event.AccountID, event.Type)
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
