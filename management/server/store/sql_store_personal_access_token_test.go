package store

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

func Test_GetTokenIDByHashedToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "../testdata/store.sql", func(t *testing.T, store Store) {
		hashed := "SoMeHaShEdToKeN"
		id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

		token, err := store.GetTokenIDByHashedToken(context.Background(), hashed)
		require.NoError(t, err)
		require.Equal(t, id, token)

		_, err = store.GetTokenIDByHashedToken(context.Background(), "non-existing-hash")
		require.Error(t, err)
		parsedErr, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
	})
}

func TestPostgresql_GetTokenIDByHashedToken(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	hashed := "SoMeHaShEdToKeN"
	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	token, err := store.GetTokenIDByHashedToken(context.Background(), hashed)
	require.NoError(t, err)
	require.Equal(t, id, token)
}

func TestSqlStore_GetPATByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"

	tests := []struct {
		name        string
		patID       string
		expectError bool
	}{
		{
			name:        "retrieve existing PAT",
			patID:       "9dj38s35-63fb-11ec-90d6-0242ac120003",
			expectError: false,
		},
		{
			name:        "retrieve non-existing PAT",
			patID:       "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty PAT ID",
			patID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pat, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, tt.patID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, pat)
			} else {
				require.NoError(t, err)
				require.NotNil(t, pat)
				require.Equal(t, tt.patID, pat.ID)
			}
		})
	}
}

func TestSqlStore_GetUserPATs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userPATs, err := store.GetUserPATs(context.Background(), LockingStrengthNone, "f4f6d672-63fb-11ec-90d6-0242ac120003")
	require.NoError(t, err)
	require.Len(t, userPATs, 1)
}

func TestSqlStore_GetPATByHashedToken(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	pat, err := store.GetPATByHashedToken(context.Background(), LockingStrengthNone, "SoMeHaShEdToKeN")
	require.NoError(t, err)
	require.Equal(t, "9dj38s35-63fb-11ec-90d6-0242ac120003", pat.ID)
}

func TestSqlStore_MarkPATUsed(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"
	patID := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	err = store.MarkPATUsed(context.Background(), patID)
	require.NoError(t, err)

	pat, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, patID)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.WithinRange(t, pat.LastUsed.UTC(), now.Add(-15*time.Second), now, "LastUsed should be within 1 second of now")
}

func TestSqlStore_SavePAT(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	pat := &types.PersonalAccessToken{
		ID:             "pat-id",
		UserID:         userID,
		Name:           "token",
		HashedToken:    "SoMeHaShEdToKeN",
		ExpirationDate: util.ToPtr(time.Now().UTC().Add(12 * time.Hour)),
		CreatedBy:      userID,
		CreatedAt:      time.Now().UTC().Add(time.Hour),
		LastUsed:       util.ToPtr(time.Now().UTC().Add(-15 * time.Minute)),
	}
	err = store.SavePAT(context.Background(), pat)
	require.NoError(t, err)

	savePAT, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, pat.ID)
	require.NoError(t, err)
	require.Equal(t, pat.ID, savePAT.ID)
	require.Equal(t, pat.UserID, savePAT.UserID)
	require.Equal(t, pat.HashedToken, savePAT.HashedToken)
	require.Equal(t, pat.CreatedBy, savePAT.CreatedBy)
	require.WithinDurationf(t, pat.GetExpirationDate(), savePAT.ExpirationDate.UTC(), time.Millisecond, "ExpirationDate should be equal")
	require.WithinDurationf(t, pat.CreatedAt, savePAT.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	require.WithinDurationf(t, pat.GetLastUsed(), savePAT.LastUsed.UTC(), time.Millisecond, "LastUsed should be equal")
}

func TestSqlStore_DeletePAT(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"
	patID := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	err = store.DeletePAT(context.Background(), userID, patID)
	require.NoError(t, err)

	pat, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, patID)
	require.Error(t, err)
	require.Nil(t, pat)
}
