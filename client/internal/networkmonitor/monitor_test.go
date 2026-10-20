package networkmonitor

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
		_, resErr = nw.Listen(context.Background(), NextHops{})
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
		_, resErr = nw.Listen(context.Background(), NextHops{})
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
		if _, resErr := nw.Listen(context.Background(), NextHops{}); resErr != nil {
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

	change, err := nw.Listen(context.Background(), NextHops{})
	require.NoError(t, err)
	assert.Equal(t, ChangeWake, change.Kind, "a wake-up must be reported as its own kind")
}

func TestNetworkMonitor_ChangeBetweenRounds(t *testing.T) {
	// The checker never fires, as when the change happened before this round
	// subscribed. The baseline points at an interface that does not exist, so
	// the current snapshot differs from it and Listen must still report.
	checkChangeFn = func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		<-ctx.Done()
		return ctx.Err()
	}
	current, err := readSnapshot()
	if err != nil || !current.HasDefault() {
		t.Skip("this host has no default route to compare with")
	}
	stale := NextHops{V4: systemops.Nexthop{IP: netip.MustParseAddr("192.0.2.1"), Intf: &net.Interface{Index: 99999, Name: "gone0"}}}

	nw := New()
	defer nw.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*debounceTime)
	defer cancel()
	change, err := nw.Listen(ctx, stale)
	require.NoError(t, err, "a change between rounds must be reported, not time out")
	assert.Equal(t, ChangeInterface, change.Kind, "the default moved away from the stale interface")
}
