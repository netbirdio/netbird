package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/netbirdio/netbird/management/server/activity"

	"github.com/stretchr/testify/require"
)

func setupDatabase(t *testing.T) *sql.DB {
	t.Helper()

	dbFile := filepath.Join(t.TempDir(), eventSinkDB)
	db, err := sql.Open("sqlite3", dbFile)
	require.NoError(t, err, "Failed to open database")

	t.Cleanup(func() {
		_ = db.Close()
	})

	_, err = db.Exec(createTableQuery)
	require.NoError(t, err, "Failed to create events table")

	_, err = db.Exec(`CREATE TABLE deleted_users (id TEXT NOT NULL, email TEXT NOT NULL, name TEXT);`)
	require.NoError(t, err, "Failed to create deleted_users table")

	return db
}

func TestMigrate(t *testing.T) {
	db := setupDatabase(t)

	key, err := GenerateKey()
	require.NoError(t, err, "Failed to generate key")

	crypt, err := NewFieldEncrypt(key)
	require.NoError(t, err, "Failed to initialize FieldEncrypt")

	legacyEmail := crypt.LegacyEncrypt("testaccount@test.com")
	legacyName := crypt.LegacyEncrypt("Test Account")

	_, err = db.Exec(`INSERT INTO events(activity, timestamp, initiator_id, target_id, account_id, meta) VALUES(?, ?, ?, ?, ?, ?)`,
		activity.UserDeleted, time.Now(), "initiatorID", "targetID", "accountID", "")
	require.NoError(t, err, "Failed to insert event")

	_, err = db.Exec(`INSERT INTO deleted_users(id, email, name) VALUES(?, ?, ?)`, "targetID", legacyEmail, legacyName)
	require.NoError(t, err, "Failed to insert legacy encrypted data")

	colExists, err := checkColumnExists(db, "deleted_users", "enc_algo")
	require.NoError(t, err, "Failed to check if enc_algo column exists")
	require.False(t, colExists, "enc_algo column should not exist before migration")

	err = migrate(context.Background(), crypt, db)
	require.NoError(t, err, "Migration failed")

	colExists, err = checkColumnExists(db, "deleted_users", "enc_algo")
	require.NoError(t, err, "Failed to check if enc_algo column exists after migration")
	require.True(t, colExists, "enc_algo column should exist after migration")

	var encAlgo string
	err = db.QueryRow(`SELECT enc_algo FROM deleted_users LIMIT 1`, "").Scan(&encAlgo)
	require.NoError(t, err, "Failed to select updated data")
	require.Equal(t, gcmEncAlgo, encAlgo, "enc_algo should be set to 'GCM' after migration")

	store, err := createStore(crypt, db)
	require.NoError(t, err, "Failed to create store")

	events, err := store.Get(context.Background(), "accountID", 0, 1, false)
	require.NoError(t, err, "Failed to get events")

	require.Len(t, events, 1, "Should have one event")
	require.Equal(t, activity.UserDeleted, events[0].Activity, "activity should match")
	require.Equal(t, "initiatorID", events[0].InitiatorID, "initiator id should match")
	require.Equal(t, "targetID", events[0].TargetID, "target id should match")
	require.Equal(t, "accountID", events[0].AccountID, "account id should match")
	require.Equal(t, "testaccount@test.com", events[0].Meta["email"], "email should match")
	require.Equal(t, "Test Account", events[0].Meta["username"], "username should match")
}
