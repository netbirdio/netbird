//go:build windows

package sleep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerFake inserts a detector into the registry without touching the OS,
// so dispatch routing can be exercised in isolation. It returns the handle and
// a cleanup that removes the entry.
func registerFake(t *testing.T, cb func(EventType)) (int, func()) {
	t.Helper()

	registryMu.Lock()
	nextHandle++
	handle := nextHandle
	d := &Detector{callback: cb, done: make(chan struct{}), handle: handle}
	registry[handle] = d
	registryMu.Unlock()

	return handle, func() {
		registryMu.Lock()
		delete(registry, handle)
		registryMu.Unlock()
	}
}

func TestPowerCallback_MapsMessageTypes(t *testing.T) {
	tests := []struct {
		name    string
		msgType uintptr
		want    EventType
		fires   bool
	}{
		{"suspend", pbtAPMSuspend, EventTypeSleep, true},
		{"resume automatic", pbtAPMResumeAutomatic, EventTypeWakeUp, true},
		{"resume suspend", pbtAPMResumeSuspend, EventTypeWakeUp, true},
		{"unknown", 0x9999, EventTypeUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan EventType, 1)
			handle, cleanup := registerFake(t, func(e EventType) { got <- e })
			defer cleanup()

			ret := powerCallback(uintptr(handle), tt.msgType, 0)
			require.Equal(t, uintptr(0), ret, "callback must return ERROR_SUCCESS")

			if !tt.fires {
				assert.Empty(t, got, "no event should fire for unhandled message type")
				return
			}
			select {
			case e := <-got:
				assert.Equal(t, tt.want, e, "mapped event type should match")
			default:
				t.Fatal("expected callback to fire")
			}
		})
	}
}

func TestDispatchEvent_UnknownHandleNoPanic(t *testing.T) {
	require.NotPanics(t, func() {
		dispatchEvent(-1, EventTypeSleep)
	}, "dispatch for an unregistered handle must be a no-op")
}

func TestTriggerCallback_SkipsAfterDone(t *testing.T) {
	done := make(chan struct{})
	close(done)

	fired := false
	d := &Detector{}
	d.triggerCallback(EventTypeSleep, func(EventType) { fired = true }, done)

	assert.False(t, fired, "callback must not run once the detector is done")
}
