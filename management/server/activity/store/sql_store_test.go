package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/util/crypt"
)

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

func TestUpdateUserID(t *testing.T) {
	ctx := context.Background()

	newStore := func(t *testing.T) *Store {
		t.Helper()
		key, _ := crypt.GenerateKey()
		s, err := NewSqlStore(ctx, t.TempDir(), key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close(ctx) }) //nolint
		return s
	}

	t.Run("updates initiator_id in events", func(t *testing.T) {
		store := newStore(t)
		accountID := "account_1"

		_, err := store.Save(ctx, &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "old-user",
			TargetID:    "some-peer",
			AccountID:   accountID,
		})
		assert.NoError(t, err)

		err = store.UpdateUserID(ctx, "old-user", "new-user")
		assert.NoError(t, err)

		result, err := store.Get(ctx, accountID, 0, 10, false)
		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "new-user", result[0].InitiatorID)
	})

	t.Run("updates target_id in events", func(t *testing.T) {
		store := newStore(t)
		accountID := "account_1"

		_, err := store.Save(ctx, &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "some-admin",
			TargetID:    "old-user",
			AccountID:   accountID,
		})
		assert.NoError(t, err)

		err = store.UpdateUserID(ctx, "old-user", "new-user")
		assert.NoError(t, err)

		result, err := store.Get(ctx, accountID, 0, 10, false)
		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "new-user", result[0].TargetID)
	})

	t.Run("updates deleted_users id", func(t *testing.T) {
		store := newStore(t)
		accountID := "account_1"

		// Save an event with email/name meta to create a deleted_users row for "old-user"
		_, err := store.Save(ctx, &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "admin",
			TargetID:    "old-user",
			AccountID:   accountID,
			Meta: map[string]any{
				"email": "user@example.com",
				"name":  "Test User",
			},
		})
		assert.NoError(t, err)

		err = store.UpdateUserID(ctx, "old-user", "new-user")
		assert.NoError(t, err)

		// Save another event referencing new-user with email/name meta.
		// This should upsert (not conflict) because the PK was already migrated.
		_, err = store.Save(ctx, &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "admin",
			TargetID:    "new-user",
			AccountID:   accountID,
			Meta: map[string]any{
				"email": "user@example.com",
				"name":  "Test User",
			},
		})
		assert.NoError(t, err)

		// The deleted user info should be retrievable via Get (joined on target_id)
		result, err := store.Get(ctx, accountID, 0, 10, false)
		assert.NoError(t, err)
		assert.Len(t, result, 2)
		for _, ev := range result {
			assert.Equal(t, "new-user", ev.TargetID)
		}
	})

	t.Run("no-op when old user ID does not exist", func(t *testing.T) {
		store := newStore(t)

		err := store.UpdateUserID(ctx, "nonexistent-user", "new-user")
		assert.NoError(t, err)
	})

	t.Run("only updates matching user leaves others unchanged", func(t *testing.T) {
		store := newStore(t)
		accountID := "account_1"

		_, err := store.Save(ctx, &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "user-a",
			TargetID:    "peer-1",
			AccountID:   accountID,
		})
		assert.NoError(t, err)

		_, err = store.Save(ctx, &activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    activity.PeerAddedByUser,
			InitiatorID: "user-b",
			TargetID:    "peer-2",
			AccountID:   accountID,
		})
		assert.NoError(t, err)

		err = store.UpdateUserID(ctx, "user-a", "user-a-new")
		assert.NoError(t, err)

		result, err := store.Get(ctx, accountID, 0, 10, false)
		assert.NoError(t, err)
		assert.Len(t, result, 2)

		for _, ev := range result {
			if ev.TargetID == "peer-1" {
				assert.Equal(t, "user-a-new", ev.InitiatorID)
			} else {
				assert.Equal(t, "user-b", ev.InitiatorID)
			}
		}
	})
}
