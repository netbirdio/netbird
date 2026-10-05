package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestSave_CancellationWhileWaitingForConnection(t *testing.T) {
	t.Setenv(storeEngineEnv, "sqlite")
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	store, err := NewSqlStore(context.Background(), t.TempDir(), key)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close(context.Background())) })
	db, err := store.db.DB()
	require.NoError(t, err)
	conn, err := db.Conn(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := store.Save(ctx, &activity.Event{
			Timestamp: time.Now().UTC(), Activity: activity.CustomDomainValidationExpired,
			AccountID: "account-id", TargetID: "domain-id", InitiatorID: activity.SystemInitiator,
		})
		result <- err
	}()
	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		require.NoError(t, conn.Close())
	case <-time.After(time.Second):
		// Release the connection so a regression cannot leave the writer running.
		require.NoError(t, conn.Close())
		assert.ErrorIs(t, <-result, context.DeadlineExceeded)
		t.Error("activity writes must stop waiting when their deadline expires")
	}
	events, err := store.Get(context.Background(), "account-id", 0, 10, true)
	require.NoError(t, err)
	assert.Empty(t, events, "a timed-out write must not persist after the connection is released")
}

func TestNewSqlStore(t *testing.T) {
	dataDir := t.TempDir()
	key, _ := crypt.GenerateKey()
	store, err := NewSqlStore(context.Background(), dataDir, key)
	if err != nil {
		t.Fatal(err)
		return
	}
	defer store.Close(context.Background()) //nolint

	accountID := "account_1"

	for i := 0; i < 10; i++ {
		_, err = store.Save(context.Background(), &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "user_" + fmt.Sprint(i),
			TargetID:    "peer_" + fmt.Sprint(i),
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatal(err)
			return
		}
	}

	result, err := store.Get(context.Background(), accountID, 0, 10, false)
	if err != nil {
		t.Fatal(err)
		return
	}

	assert.Len(t, result, 10)
	assert.True(t, result[0].Timestamp.Before(result[len(result)-1].Timestamp))

	result, err = store.Get(context.Background(), accountID, 0, 5, true)
	if err != nil {
		t.Fatal(err)
		return
	}

	assert.Len(t, result, 5)
	assert.True(t, result[0].Timestamp.After(result[len(result)-1].Timestamp))
}
