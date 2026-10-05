package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestStoreEvent_CanceledContext(t *testing.T) {
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	t.Setenv("NB_ACTIVITY_EVENT_STORE_ENGINE", "sqlite")
	for _, code := range []activity.Activity{activity.CustomDomainValidationExpired, activity.DomainAdded} {
		t.Run(code.StringCode(), func(t *testing.T) {
			dir := t.TempDir()
			key, err := crypt.GenerateKey()
			require.NoError(t, err)
			eventStore, err := activitystore.NewSqlStore(context.Background(), dir, key)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, eventStore.Close(context.Background())) })
			manager := &DefaultAccountManager{eventStore: eventStore}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			// The operation already succeeded when shutdown or the request cancels its context.
			manager.StoreEvent(ctx, activity.SystemInitiator, "domain-id", "account-id",
				code, map[string]any{"domain": "expired.example.com"})
			if code != activity.CustomDomainValidationExpired {
				require.Eventually(t, func() bool {
					events, err := eventStore.Get(context.Background(), "account-id", 0, 10, true)
					return err == nil && len(events) == 1
				}, time.Second, time.Millisecond, "asynchronous events must survive request cancellation")
			}
			require.NoError(t, eventStore.Close(context.Background()))

			reopened, err := activitystore.NewSqlStore(context.Background(), dir, key)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, reopened.Close(context.Background())) })
			events, err := reopened.Get(context.Background(), "account-id", 0, 10, true)
			require.NoError(t, err)
			require.Len(t, events, 1, "the event must be persisted before shutdown closes the store")
			assert.Equal(t, code, events[0].Activity, "persist the requested activity")
			assert.Equal(t, "domain-id", events[0].TargetID, "retain the registration ID")
			assert.Equal(t, "expired.example.com", events[0].Meta["domain"], "retain the domain name")
		})
	}
}

func generateAndStoreEvents(t *testing.T, manager *DefaultAccountManager, typ activity.Activity, initiatorID, targetID,
	accountID string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		_, err := manager.eventStore.Save(context.Background(), &activity.Event{
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
	manager, _, err := createManager(t)
	if err != nil {
		return
	}

	accountID := "accountID"

	t.Run("get empty events list", func(t *testing.T) {
		events, err := manager.GetEvents(context.Background(), accountID, userID)
		if err != nil {
			return
		}
		assert.Len(t, events, 0)
		_ = manager.eventStore.Close(context.Background()) //nolint
	})

	t.Run("get events", func(t *testing.T) {
		generateAndStoreEvents(t, manager, activity.PeerAddedByUser, userID, "peer", accountID, 10)
		events, err := manager.GetEvents(context.Background(), accountID, userID)
		if err != nil {
			return
		}

		assert.Len(t, events, 10)
		_ = manager.eventStore.Close(context.Background()) //nolint
	})

	t.Run("get events without duplicates", func(t *testing.T) {
		generateAndStoreEvents(t, manager, activity.UserJoined, userID, "", accountID, 10)
		events, err := manager.GetEvents(context.Background(), accountID, userID)
		if err != nil {
			return
		}
		assert.Len(t, events, 1)
		_ = manager.eventStore.Close(context.Background()) //nolint
	})
}
