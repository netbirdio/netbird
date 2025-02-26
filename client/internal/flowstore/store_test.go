package flowstore_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/flowstore"
)

func TestStore(t *testing.T) {
	store := flowstore.New(context.Background())
	t.Cleanup(func() {
		store.Close()
	})

	event := flowstore.EventFields{
		FlowID:    uuid.New(),
		Type:      flowstore.TypeStart,
		Direction: flowstore.Ingress,
		Protocol:  6,
	}

	store.StoreEvent(event)
	allEvents := store.GetEvents()
	for _, e := range allEvents {
		if e.EventFields.FlowID != event.FlowID {
			t.Errorf("expected event ID %s, got %s", event.FlowID, e.ID)
		}
	}
}
