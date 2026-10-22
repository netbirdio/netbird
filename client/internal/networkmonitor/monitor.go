//go:build !ios && !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

const (
	debounceTime = 2 * time.Second
)

var checkChangeFn = checkChange

// NetworkMonitor watches for changes in network configuration.
type NetworkMonitor struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex

	// nexthopChanged reports whether the default next hop changed; overridable in tests.
	nexthopChanged func(oldv4, oldv6 systemops.Nexthop) bool
}

// New creates a new network monitor.
func New() *NetworkMonitor {
	return &NetworkMonitor{
		nexthopChanged: nexthopChanged,
	}
}

// Listen begins monitoring network changes. When a change is detected, this function will return without error.
func (nw *NetworkMonitor) Listen(ctx context.Context) (err error) {
	nw.mu.Lock()
	if nw.cancel != nil {
		nw.mu.Unlock()
		return errors.New("network monitor already started")
	}

	ctx, nw.cancel = context.WithCancel(ctx)
	defer nw.cancel()
	nw.wg.Add(1)
	nw.mu.Unlock()

	defer nw.wg.Done()

	var nexthop4, nexthop6 systemops.Nexthop

	operation := func() error {
		var errv4, errv6 error
		nexthop4, errv4 = systemops.GetNextHop(netip.IPv4Unspecified())
		nexthop6, errv6 = systemops.GetNextHop(netip.IPv6Unspecified())

		if errv4 != nil && errv6 != nil {
			return errors.New("failed to get default next hops")
		}

		if errv4 == nil {
			log.Debugf("Network monitor: IPv4 default route: %s, interface: %s", nexthop4.IP, nexthop4.Intf.Name)
		}
		if errv6 == nil {
			log.Debugf("Network monitor: IPv6 default route: %s, interface: %s", nexthop6.IP, nexthop6.Intf.Name)
		}

		// continue if either route was found
		return nil
	}

	expBackOff := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)

	if err := backoff.Retry(operation, expBackOff); err != nil {
		return fmt.Errorf("failed to get default next hops: %w", err)
	}

	// recover in case sys ops panic
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occurred: %v, stack trace: %s", r, debug.Stack())
		}
	}()

	event := make(chan struct{}, 1)
	go nw.checkChanges(ctx, event, nexthop4, nexthop6)

	log.Infof("start watching for network changes")
	// debounce changes
	timer := time.NewTimer(0)
	timer.Stop()
	for {
		select {
		case <-event:
			timer.Reset(debounceTime)
		case <-timer.C:
			// A flapping NIC may return to the same default route after the
			// debounce window; only restart if the next hop actually changed.
			if nw.nexthopChanged(nexthop4, nexthop6) {
				return nil
			}
			log.Debug("Network monitor: default route unchanged after debounce, ignoring")
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
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

func (nw *NetworkMonitor) checkChanges(ctx context.Context, event chan struct{}, nexthop4 systemops.Nexthop, nexthop6 systemops.Nexthop) {
	defer close(event)
	for {
		if err := checkChangeFn(ctx, nexthop4, nexthop6); err != nil {
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

// nexthopChanged reports whether the current default next hop differs from the
// given baseline, per protocol. A failed lookup is treated as an absent route
// (zero Nexthop), so a protocol that had no default route to begin with (e.g.
// IPv6 in a single-stack network) does not by itself count as a change.
func nexthopChanged(oldv4, oldv6 systemops.Nexthop) bool {
	newv4, _ := systemops.GetNextHop(netip.IPv4Unspecified())
	newv6, _ := systemops.GetNextHop(netip.IPv6Unspecified())
	return !sameNexthop(oldv4, newv4) || !sameNexthop(oldv6, newv6)
}

func sameNexthop(a, b systemops.Nexthop) bool {
	if a.IP != b.IP {
		return false
	}
	if (a.Intf == nil) != (b.Intf == nil) {
		return false
	}
	if a.Intf != nil && a.Intf.Index != b.Intf.Index {
		return false
	}
	return true
}
