package store

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestSqlite_GetSetupKeyBySecret(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	plainKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	hashedKey := sha256.Sum256([]byte(plainKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	setupKey, err := store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, encodedHashedKey, setupKey.Key)
	assert.Equal(t, types.HiddenKey(plainKey, 4), setupKey.KeySecret)
	assert.Equal(t, "bf1c8084-ba50-4ce7-9439-34653001fc3b", setupKey.AccountID)
	assert.Equal(t, "Default key", setupKey.Name)
}

func TestSqlite_incrementSetupKeyUsage(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	plainKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	hashedKey := sha256.Sum256([]byte(plainKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	setupKey, err := store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 0, setupKey.UsedTimes)

	err = store.IncrementSetupKeyUsage(context.Background(), setupKey.Id)
	require.NoError(t, err)

	setupKey, err = store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 1, setupKey.UsedTimes)

	err = store.IncrementSetupKeyUsage(context.Background(), setupKey.Id)
	require.NoError(t, err)

	setupKey, err = store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 2, setupKey.UsedTimes)
}

func Test_DeleteSetupKeySuccessfully(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	setupKeyID := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	err = store.DeleteSetupKey(context.Background(), accountID, setupKeyID)
	require.NoError(t, err)

	_, err = store.GetSetupKeyByID(context.Background(), LockingStrengthNone, setupKeyID, accountID)
	require.Error(t, err)
}

func Test_DeleteSetupKeyFailsForNonExistingKey(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nonExistingKeyID := "non-existing-key-id"

	err = store.DeleteSetupKey(context.Background(), accountID, nonExistingKeyID)
	require.Error(t, err)
}
