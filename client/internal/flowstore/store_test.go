package flowstore_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/client/internal/flowstore"
)

func TestStore(t *testing.T) {
	store := flowstore.New(context.Background())
	t.Cleanup(func() {
		store.Close()
	})

	event := flowstore.Event{
		ID:     "1",
		FlowID: "1",
	}

	store.StoreEvent(event)
	allEvents := store.GetEvents()
	for _, e := range allEvents {
		if e.ID != event.ID {
			t.Errorf("expected event ID %s, got %s", event.ID, e.ID)
		}
	}
}
