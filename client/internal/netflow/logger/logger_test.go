package logger_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

func TestStore(t *testing.T) {
	logger := logger.New(context.Background())
	logger.Enable()

	event := types.EventFields{
		FlowID:    uuid.New(),
		Type:      types.TypeStart,
		Direction: types.Ingress,
		Protocol:  6,
	}
	time.Sleep(time.Millisecond)
	logger.StoreEvent(event)
	time.Sleep(time.Millisecond)

	allEvents := logger.GetEvents()
	matched := false
	for _, e := range allEvents {
		if e.EventFields.FlowID == event.FlowID {
			matched = true
		}
	}
	if !matched {
		t.Errorf("didn't match any event")
	}
}
