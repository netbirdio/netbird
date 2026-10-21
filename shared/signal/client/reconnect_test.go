package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReconnectListenerCanBeClearedWhileCallbackIsBlocked(t *testing.T) {
	client := &GrpcClient{}
	var listenerMu sync.Mutex
	callbackStarted := make(chan struct{})
	callbackFinished := make(chan struct{})
	callbackCalls := 0
	client.SetOnReconnectedListener(func() {
		callbackCalls++
		close(callbackStarted)
		listenerMu.Lock()
		close(callbackFinished)
		listenerMu.Unlock()
	})

	// SRWatcher.Close holds its own mutex while removing the listener. A
	// reconnect callback waiting for that mutex must not block its removal.
	listenerMu.Lock()
	notificationDone := make(chan struct{})
	go func() {
		defer close(notificationDone)
		client.notifyStreamConnected()
	}()
	var unregisterDone chan struct{}
	t.Cleanup(func() {
		// Release the callback even when the regression assertion fails, so
		// the unfixed implementation does not leave deadlocked goroutines.
		listenerMu.Unlock()
		select {
		case <-notificationDone:
			select {
			case <-callbackFinished:
			default:
				t.Error("in-flight callback did not finish after listener removal")
			}
		case <-time.After(5 * time.Second):
			t.Error("reconnect notification did not finish after releasing the listener")
		}
		if unregisterDone != nil {
			select {
			case <-unregisterDone:
			case <-time.After(5 * time.Second):
				t.Error("listener removal did not finish after releasing the listener")
			}
		}
	})

	select {
	case <-callbackStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect callback did not start")
	}

	unregisterDone = make(chan struct{})
	go func() {
		client.SetOnReconnectedListener(nil)
		close(unregisterDone)
	}()
	select {
	case <-unregisterDone:
	case <-time.After(5 * time.Second):
		t.Fatal("listener removal blocked behind the reconnect callback")
	}

	// Registration still becomes visible, and future notifications do not
	// invoke the removed listener even while its first callback is in flight.
	assert.True(t, client.StreamConnected(), "listener removal must preserve stream registration")
	client.notifyStreamConnected()
	assert.Equal(t, 1, callbackCalls, "future notifications must not invoke the removed listener")
}

func TestReconnectListenerRunsAfterRegistrationWaitersAreReleased(t *testing.T) {
	connected := make(chan struct{})
	client := &GrpcClient{connectedCh: connected}
	called := false
	client.SetOnReconnectedListener(func() {
		called = true
		select {
		case <-connected:
		default:
			t.Error("reconnect callback ran before registration waiters were released")
		}
	})

	client.notifyStreamConnected()

	assert.True(t, called, "reconnect notification must invoke its listener synchronously")
	assert.True(t, client.StreamConnected(), "stream must remain registered after the callback")
}
