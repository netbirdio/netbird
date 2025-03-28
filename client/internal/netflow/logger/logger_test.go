package logger_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

func TestStore(t *testing.T) {
	logger := logger.New(nil, net.IPNet{})
	logger.Enable()

	event := types.EventFields{
		FlowID:    uuid.New(),
		Type:      types.TypeStart,
		Direction: types.Ingress,
		Protocol:  6,
	}

	wait := func() { time.Sleep(time.Millisecond) }
	wait()
	logger.StoreEvent(event)
	wait()

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

	// test disable
	logger.Close()
	wait()
	logger.StoreEvent(event)
	wait()
	allEvents = logger.GetEvents()
	if len(allEvents) != 0 {
		t.Errorf("expected 0 events, got %d", len(allEvents))
	}

	// test re-enable
	logger.Enable()
	wait()
	logger.StoreEvent(event)
	wait()

	allEvents = logger.GetEvents()
	matched = false
	for _, e := range allEvents {
		if e.EventFields.FlowID == event.FlowID {
			matched = true
		}
	}
	if !matched {
		t.Errorf("didn't match any event")
	}
}
