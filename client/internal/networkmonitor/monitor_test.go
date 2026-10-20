package networkmonitor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

type MocMultiEvent struct {
	counter int
}

func (m *MocMultiEvent) checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	if m.counter == 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	time.Sleep(1 * time.Second)
	m.counter--
	return nil
}

func TestNetworkMonitor_Close(t *testing.T) {
	checkChangeFn = func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		<-ctx.Done()
		return ctx.Err()
	}
	nw := New()

	var resErr error
	done := make(chan struct{})
	go func() {
		_, resErr = nw.Listen(context.Background())
		close(done)
	}()

	time.Sleep(1 * time.Second) // wait for the goroutine to start
	nw.Stop()

	<-done
	if !errors.Is(resErr, context.Canceled) {
		t.Errorf("unexpected error: %v", resErr)
	}
}

func TestNetworkMonitor_Event(t *testing.T) {
	checkChangeFn = func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.Done():
			return nil
		}
	}
	nw := New()
	defer nw.Stop()

	var resErr error
	done := make(chan struct{})
	go func() {
		_, resErr = nw.Listen(context.Background())
		close(done)
	}()

	<-done
	if !errors.Is(resErr, nil) {
		t.Errorf("unexpected error: %v", nil)
	}
}

func TestNetworkMonitor_MultiEvent(t *testing.T) {
	eventsRepeated := 3
	me := &MocMultiEvent{counter: eventsRepeated}
	checkChangeFn = me.checkChange

	nw := New()
	defer nw.Stop()

	done := make(chan struct{})
	started := time.Now()
	go func() {
		if _, resErr := nw.Listen(context.Background()); resErr != nil {
			t.Errorf("unexpected error: %v", resErr)
		}
		close(done)
	}()

	<-done
	expectedResponseTime := time.Duration(eventsRepeated)*time.Second + debounceTime
	if time.Since(started) < expectedResponseTime {
		t.Errorf("unexpected duration: %v", time.Since(started))
	}
}

func TestNetworkMonitor_WakeUp(t *testing.T) {
	// The first check reports a wake-up instead of a route change; the next
	// one blocks, as a real checker does until the following event.
	var calls atomic.Int32
	checkChangeFn = func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		if calls.Add(1) == 1 {
			return errWokeUp
		}
		<-ctx.Done()
		return ctx.Err()
	}
	nw := New()
	defer nw.Stop()

	change, err := nw.Listen(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ChangeWake, change.Kind, "a wake-up must be reported as its own kind")
}
