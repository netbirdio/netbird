package networkmonitor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

type MocMultiEvent struct {
	counter       int
	watcherExited chan struct{}
}

func useTestNextHop(t *testing.T) {
	t.Helper()

	previousGetNextHopFn := getNextHopFn
	getNextHopFn = func(netip.Addr) (systemops.Nexthop, error) {
		return systemops.Nexthop{Intf: &net.Interface{Name: "test"}}, nil
	}
	t.Cleanup(func() {
		getNextHopFn = previousGetNextHopFn
	})
}

func useTestCheckChange(t *testing.T, fn func(context.Context, systemops.Nexthop, systemops.Nexthop) error) {
	t.Helper()

	previousCheckChangeFn := checkChangeFn
	checkChangeFn = fn
	t.Cleanup(func() {
		checkChangeFn = previousCheckChangeFn
	})
}

func (m *MocMultiEvent) checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	if m.counter == 0 {
		<-ctx.Done()
		close(m.watcherExited)
		return ctx.Err()
	}

	time.Sleep(1 * time.Second)
	m.counter--
	return nil
}

func TestNetworkMonitor_Close(t *testing.T) {
	useTestNextHop(t)

	watcherExited := make(chan struct{})
	useTestCheckChange(t, func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		<-ctx.Done()
		close(watcherExited)
		return ctx.Err()
	})
	nw := New()

	var resErr error
	done := make(chan struct{})
	go func() {
		resErr = nw.Listen(context.Background())
		close(done)
	}()

	time.Sleep(1 * time.Second) // wait for the goroutine to start
	nw.Stop()

	<-done
	<-watcherExited
	if !errors.Is(resErr, context.Canceled) {
		t.Errorf("unexpected error: %v", resErr)
	}
}

func TestNetworkMonitor_Event(t *testing.T) {
	useTestNextHop(t)

	watcherExited := make(chan struct{})
	useTestCheckChange(t, func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		select {
		case <-ctx.Done():
			close(watcherExited)
			return ctx.Err()
		case <-timeout.Done():
			return nil
		}
	})
	nw := New()
	defer nw.Stop()

	var resErr error
	done := make(chan struct{})
	go func() {
		resErr = nw.Listen(context.Background())
		close(done)
	}()

	<-done
	<-watcherExited
	if !errors.Is(resErr, nil) {
		t.Errorf("unexpected error: %v", nil)
	}
}

func TestNetworkMonitor_MultiEvent(t *testing.T) {
	useTestNextHop(t)

	eventsRepeated := 3
	me := &MocMultiEvent{counter: eventsRepeated, watcherExited: make(chan struct{})}
	useTestCheckChange(t, me.checkChange)

	nw := New()
	defer nw.Stop()

	done := make(chan struct{})
	started := time.Now()
	go func() {
		if resErr := nw.Listen(context.Background()); resErr != nil {
			t.Errorf("unexpected error: %v", resErr)
		}
		close(done)
	}()

	<-done
	<-me.watcherExited
	expectedResponseTime := time.Duration(eventsRepeated)*time.Second + debounceTime
	if time.Since(started) < expectedResponseTime {
		t.Errorf("unexpected duration: %v", time.Since(started))
	}
}

func TestNetworkMonitor_WatcherDoesNotCloseEvents(t *testing.T) {
	watcherErr := errors.New("watcher failed")
	useTestCheckChange(t, func(context.Context, systemops.Nexthop, systemops.Nexthop) error {
		return watcherErr
	})

	events := make(chan struct{}, 1)
	watchErrors := make(chan error, 1)
	New().checkChanges(context.Background(), events, watchErrors, systemops.Nexthop{}, systemops.Nexthop{})

	select {
	case got := <-watchErrors:
		if !errors.Is(got, watcherErr) {
			t.Fatalf("watcher error = %v, want %v", got, watcherErr)
		}
	default:
		t.Fatal("watcher error was not delivered")
	}

	select {
	case got := <-watchErrors:
		t.Fatalf("watcher error delivered more than once: %v", got)
	default:
	}

	select {
	case _, ok := <-events:
		if !ok {
			t.Fatal("event channel was closed by watcher")
		}
	default:
	}
}

func TestNetworkMonitor_WatcherError(t *testing.T) {
	watcherErr := errors.New("watcher failed")
	previousGetNextHopFn := getNextHopFn
	useTestCheckChange(t, func(context.Context, systemops.Nexthop, systemops.Nexthop) error {
		return watcherErr
	})
	getNextHopFn = func(netip.Addr) (systemops.Nexthop, error) {
		return systemops.Nexthop{Intf: &net.Interface{Name: "test"}}, nil
	}
	t.Cleanup(func() {
		getNextHopFn = previousGetNextHopFn
	})

	err := New().Listen(context.Background())
	if !errors.Is(err, watcherErr) {
		t.Fatalf("Listen() error = %v, want wrapped %v", err, watcherErr)
	}
}

func TestNetworkMonitor_WatcherCanceledWithoutListenerCancellation(t *testing.T) {
	useTestNextHop(t)

	useTestCheckChange(t, func(context.Context, systemops.Nexthop, systemops.Nexthop) error {
		return context.Canceled
	})

	err := New().Listen(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Listen() error = %v, want wrapped %v", err, context.Canceled)
	}
}

func TestUseTestCheckChangeRestoresPreviousValue(t *testing.T) {
	previousErr := errors.New("previous watcher")
	useTestCheckChange(t, func(context.Context, systemops.Nexthop, systemops.Nexthop) error {
		return previousErr
	})

	overrideErr := errors.New("override watcher")
	t.Run("override", func(t *testing.T) {
		useTestCheckChange(t, func(context.Context, systemops.Nexthop, systemops.Nexthop) error {
			return overrideErr
		})

		if got := checkChangeFn(context.Background(), systemops.Nexthop{}, systemops.Nexthop{}); !errors.Is(got, overrideErr) {
			t.Fatalf("checkChangeFn() error = %v, want %v", got, overrideErr)
		}
	})

	if got := checkChangeFn(context.Background(), systemops.Nexthop{}, systemops.Nexthop{}); !errors.Is(got, previousErr) {
		t.Fatalf("checkChangeFn() error after cleanup = %v, want %v", got, previousErr)
	}
}
