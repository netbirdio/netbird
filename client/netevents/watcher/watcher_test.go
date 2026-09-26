package watcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventKind_String(t *testing.T) {
	tests := []struct {
		kind     EventKind
		expected string
	}{
		{EventNetworkDisconnected, "NetworkDisconnected"},
		{EventNetworkConnected, "NetworkConnected"},
		{EventUnderlyingVPNDisconnected, "UnderlyingVPNDisconnected"},
		{EventUnderlyingVPNConnected, "UnderlyingVPNConnected"},
		{EventNetBirdInterfaceDisconnected, "NetBirdInterfaceDisconnected"},
		{EventKind(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.kind.String())
		})
	}
}

func TestHandlerFunc(t *testing.T) {
	var received Event
	var mu sync.Mutex

	handler := HandlerFunc(func(ev Event) {
		mu.Lock()
		received = ev
		mu.Unlock()
	})

	testEvent := Event{
		Kind:          EventUnderlyingVPNDisconnected,
		Name:          "corporate-vpn",
		Reason:        "user disconnected",
		UserInitiated: true,
	}

	handler.OnNetworkEvent(testEvent)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, testEvent.Kind, received.Kind)
	assert.Equal(t, testEvent.Name, received.Name)
	assert.Equal(t, testEvent.Reason, received.Reason)
	assert.True(t, received.UserInitiated)
}

func TestWatcher_Factory(t *testing.T) {
	w := New("wt0")
	require.NotNil(t, w, "Watcher factory should produce a non-nil watcher")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := w.Start(ctx, HandlerFunc(func(_ Event) {}))
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	err = w.Stop()
	assert.NoError(t, err)
}
