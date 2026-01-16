package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/migration"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	insertDeletedUserQuery = `INSERT INTO deleted_users (id, email, name, enc_algo) VALUES (?, ?, ?, ?)`
)

func setupDatabase(t *testing.T) *gorm.DB {
	t.Helper()

	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err, "Failed to create Postgres test container")
	t.Cleanup(cleanup)

	db, err := gorm.Open(postgres.Open(dsn))
	require.NoError(t, err)

	sql, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = sql.Close()
	})

	return db
}

func TestMigrateLegacyEncryptedUsersToGCM(t *testing.T) {
	db := setupDatabase(t)

	key, err := crypt.GenerateKey()
	require.NoError(t, err, "Failed to generate key")

	crypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err, "Failed to initialize FieldEncrypt")

	t.Run("empty table, no migration required", func(t *testing.T) {
		require.NoError(t, migrateLegacyEncryptedUsersToGCM(context.Background(), db, crypt))
		assert.False(t, db.Migrator().HasTable("deleted_users"))
	})

	require.NoError(t, db.Exec(`CREATE TABLE deleted_users (id TEXT NOT NULL, email TEXT NOT NULL, name TEXT);`).Error)
	assert.True(t, db.Migrator().HasTable("deleted_users"))
	assert.False(t, db.Migrator().HasColumn("deleted_users", "enc_algo"))

	require.NoError(t, migration.MigrateNewField[activity.DeletedUser](context.Background(), db, "enc_algo", ""))
	assert.True(t, db.Migrator().HasColumn("deleted_users", "enc_algo"))

	t.Run("legacy users migration", func(t *testing.T) {
		legacyEmail := crypt.LegacyEncrypt("test.user@test.com")
		legacyName := crypt.LegacyEncrypt("Test User")

		require.NoError(t, db.Exec(insertDeletedUserQuery, "user1", legacyEmail, legacyName, "").Error)
		require.NoError(t, db.Exec(insertDeletedUserQuery, "user2", legacyEmail, legacyName, "legacy").Error)

		require.NoError(t, migrateLegacyEncryptedUsersToGCM(context.Background(), db, crypt))

		var users []activity.DeletedUser
		require.NoError(t, db.Find(&users).Error)
		assert.Len(t, users, 2)

		for _, user := range users {
			assert.Equal(t, gcmEncAlgo, user.EncAlgo)

			decryptedEmail, err := crypt.Decrypt(user.Email)
			require.NoError(t, err)
			assert.Equal(t, "test.user@test.com", decryptedEmail)

			decryptedName, err := crypt.Decrypt(user.Name)
			require.NoError(t, err)
			require.Equal(t, "Test User", decryptedName)
		}
	})

	t.Run("users already migrated, no migration", func(t *testing.T) {
		encryptedEmail, err := crypt.Encrypt("test.user@test.com")
		require.NoError(t, err)

		encryptedName, err := crypt.Encrypt("Test User")
		require.NoError(t, err)

		require.NoError(t, db.Exec(insertDeletedUserQuery, "user3", encryptedEmail, encryptedName, gcmEncAlgo).Error)
		require.NoError(t, migrateLegacyEncryptedUsersToGCM(context.Background(), db, crypt))

		var users []activity.DeletedUser
		require.NoError(t, db.Find(&users).Error)
		assert.Len(t, users, 3)

		for _, user := range users {
			assert.Equal(t, gcmEncAlgo, user.EncAlgo)

			decryptedEmail, err := crypt.Decrypt(user.Email)
			require.NoError(t, err)
			assert.Equal(t, "test.user@test.com", decryptedEmail)

			decryptedName, err := crypt.Decrypt(user.Name)
			require.NoError(t, err)
			require.Equal(t, "Test User", decryptedName)
		}
	})
}

func TestMigrateDuplicateDeletedUsers(t *testing.T) {
	db := setupDatabase(t)

	require.NoError(t, migrateDuplicateDeletedUsers(context.Background(), db))
	assert.False(t, db.Migrator().HasTable("deleted_users"))

	require.NoError(t, db.Exec(`CREATE TABLE deleted_users (id TEXT NOT NULL, email TEXT NOT NULL, name TEXT, enc_algo TEXT NOT NULL);`).Error)
	assert.True(t, db.Migrator().HasTable("deleted_users"))

	isPrimaryKey, err := isColumnPrimaryKey[activity.DeletedUser](db, "id")
	require.NoError(t, err)
	assert.False(t, isPrimaryKey)

	require.NoError(t, db.Exec(insertDeletedUserQuery, "user1", "email1", "name1", "GCM").Error)
	require.NoError(t, db.Exec(insertDeletedUserQuery, "user1", "email2", "name2", "GCM").Error)
	require.NoError(t, migrateDuplicateDeletedUsers(context.Background(), db))

	isPrimaryKey, err = isColumnPrimaryKey[activity.DeletedUser](db, "id")
	require.NoError(t, err)
	assert.True(t, isPrimaryKey)

	var users []activity.DeletedUser
	require.NoError(t, db.Find(&users).Error)
	assert.Len(t, users, 1)
	assert.Equal(t, "user1", users[0].ID)
	assert.Equal(t, "email2", users[0].Email)
	assert.Equal(t, "name2", users[0].Name)
	assert.Equal(t, "GCM", users[0].EncAlgo)
}
