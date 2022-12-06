package event

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

const (
	SQLiteEventSinkDB = "events.db"
	createTableQuery  = "CREATE TABLE IF NOT EXISTS events " +
		"(id UNSIGNED BIG INT PRIMARY KEY AUTOINCREMENT, message TEXT, timestamp DATETIME);"
)

type SQLiteSink struct {
	db *sql.DB
}

// NewSQLiteSink creates a new SQLiteSink with an event table if not exists.
func NewSQLiteSink(dbPath string) (*SQLiteSink, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return nil, err
	}

	return &SQLiteSink{db: db}, nil
}

// Add an event to the SQLite table
func (sink *SQLiteSink) Add(event *Event) error {

	_, err := sink.db.Exec(createTableQuery)
	if err != nil {
		return err
	}

	stmt, err := sink.db.Prepare("INSERT INTO events(message, timestamp) values(?, ?)")
	if err != nil {
		return err
	}

	result, err := stmt.Exec(event.Message, event.Timestamp)
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle the case of no rows returned.
		}
		return album, err
	}

	fmt.Println(result)

	return nil
}

// Close the SQLiteSink
func (sink *SQLiteSink) Close() error {
	if sink.db != nil {
		return sink.db.Close()
	}
	return nil
}
