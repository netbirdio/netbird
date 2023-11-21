package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/activity"
)

func generateAndStoreEvents(t *testing.T, manager *DefaultAccountManager, typ activity.Activity, initiatorID, targetID,
	accountID string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		_, err := manager.eventStore.Save(&activity.Event{
			Timestamp:   time.Now().UTC(),
			Activity:    typ,
			InitiatorID: initiatorID,
			TargetID:    targetID,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDefaultAccountManager_GetEvents(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		return
	}

	accountID := "accountID"

	t.Run("get empty events list", func(t *testing.T) {
		events, err := manager.GetEvents(accountID, userID)
		if err != nil {
			return
		}
		assert.Len(t, events, 0)
		_ = manager.eventStore.Close() //nolint
	})

	t.Run("get events", func(t *testing.T) {
		generateAndStoreEvents(t, manager, activity.PeerAddedByUser, userID, "peer", accountID, 10)
		events, err := manager.GetEvents(accountID, userID)
		if err != nil {
			return
		}

		assert.Len(t, events, 10)
		_ = manager.eventStore.Close() //nolint
	})

	t.Run("get events without duplicates", func(t *testing.T) {
		generateAndStoreEvents(t, manager, activity.UserJoined, userID, "", accountID, 10)
		events, err := manager.GetEvents(accountID, userID)
		if err != nil {
			return
		}
		assert.Len(t, events, 1)
		_ = manager.eventStore.Close() //nolint
	})
}
