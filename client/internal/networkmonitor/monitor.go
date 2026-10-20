//go:build !ios && !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

const (
	debounceTime = 2 * time.Second
)

var checkChangeFn = checkChange

// errWokeUp is returned by a checkChange that detected a wake-up from sleep
// rather than a route change, so Listen can report it as its own kind.
var errWokeUp = errors.New("system woke up from sleep")

// NetworkMonitor watches for changes in network configuration.
type NetworkMonitor struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// New creates a new network monitor.
func New() *NetworkMonitor {
	return &NetworkMonitor{}
}

// Listen begins monitoring network changes. When a change is detected, it
// returns how the underlay default next hops moved. It can be called again
// after it returns, to watch for the next change from the new baseline.
func (nw *NetworkMonitor) Listen(ctx context.Context) (change Change, err error) {
	nw.mu.Lock()
	if nw.cancel != nil {
		nw.mu.Unlock()
		return Change{}, errors.New("network monitor already started")
	}

	ctx, nw.cancel = context.WithCancel(ctx)
	defer nw.release()
	nw.wg.Add(1)
	nw.mu.Unlock()

	defer nw.wg.Done()

	var nexthop4, nexthop6 systemops.Nexthop

	operation := func() error {
		var err error
		nexthop4, nexthop6, err = readNextHops()
		return err
	}

	expBackOff := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)

	if err := backoff.Retry(operation, expBackOff); err != nil {
		return Change{}, fmt.Errorf("failed to get default next hops: %w", err)
	}

	// recover in case sys ops panic
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occurred: %v, stack trace: %s", r, debug.Stack())
		}
	}()

	event := make(chan struct{}, 1)
	var woke atomic.Bool
	go nw.checkChanges(ctx, event, &woke, nexthop4, nexthop6)

	log.Infof("start watching for network changes")
	// debounce changes
	timer := time.NewTimer(0)
	timer.Stop()
	for {
		select {
		case <-event:
			timer.Reset(debounceTime)
		case <-timer.C:
			change := newChange(nexthop4, nexthop6)
			if woke.Load() {
				change.Kind = ChangeWake
			}
			return change, nil
		case <-ctx.Done():
			timer.Stop()
			return Change{}, ctx.Err()
		}
	}
}

// Stop stops the network monitor.
func (nw *NetworkMonitor) Stop() {
	nw.mu.Lock()
	defer nw.mu.Unlock()

	if nw.cancel == nil {
		return
	}

	nw.cancel()
	nw.wg.Wait()
}

// release cancels the current Listen run and clears it, so Listen can run again.
func (nw *NetworkMonitor) release() {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	nw.cancel()
	nw.cancel = nil
}

func (nw *NetworkMonitor) checkChanges(ctx context.Context, event chan struct{}, woke *atomic.Bool, nexthop4 systemops.Nexthop, nexthop6 systemops.Nexthop) {
	defer close(event)
	for {
		err := checkChangeFn(ctx, nexthop4, nexthop6)
		switch {
		case errors.Is(err, errWokeUp):
			woke.Store(true)
		case err != nil:
			if !errors.Is(err, context.Canceled) {
				log.Errorf("Network monitor: failed to check for changes: %v", err)
			}
			return
		}
		// prevent blocking
		select {
		case event <- struct{}{}:
		default:
		}
	}
}

// newChange compares the baseline next hops with the current ones. A failed
// lookup leaves After empty, which classifies as an interface change.
func newChange(nexthop4, nexthop6 systemops.Nexthop) Change {
	before := NextHops{V4: nexthop4, V6: nexthop6}
	var after NextHops
	after.V4, after.V6, _ = readNextHops()
	return Change{Kind: classify(before, after), Before: before, After: after}
}

// readNextHops returns the current underlay default next hops. It fails only
// when neither family has one.
func readNextHops() (systemops.Nexthop, systemops.Nexthop, error) {
	nexthop4, errv4 := underlayNextHop(netip.IPv4Unspecified())
	nexthop6, errv6 := underlayNextHop(netip.IPv6Unspecified())

	if errv4 != nil && errv6 != nil {
		return nexthop4, nexthop6, errors.New("failed to get default next hops")
	}

	if errv4 == nil {
		log.Debugf("Network monitor: IPv4 default route: %s, interface: %s", nexthop4.IP, nexthop4.Intf.Name)
	}
	if errv6 == nil {
		log.Debugf("Network monitor: IPv6 default route: %s, interface: %s", nexthop6.IP, nexthop6.Intf.Name)
	}

	return nexthop4, nexthop6, nil
}
