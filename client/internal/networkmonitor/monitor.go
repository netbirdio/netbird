//go:build !ios && !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"slices"
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

// readSnapshotFn reads the current underlay; tests replace it.
var readSnapshotFn = readSnapshot

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
// returns how the underlay moved. It can be called again after it returns,
// to watch for the next change. The caller passes the snapshot to compare
// with, normally the After of the previous change; an empty baseline makes
// Listen read the current one and wait until a default route exists.
func (nw *NetworkMonitor) Listen(ctx context.Context, baseline NextHops) (change Change, err error) {
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

	given := baseline.HasDefault()
	if !given {
		operation := func() error {
			var err error
			baseline, err = readSnapshotFn()
			return err
		}

		expBackOff := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)

		if err := backoff.Retry(operation, expBackOff); err != nil {
			return Change{}, fmt.Errorf("failed to get default next hops: %w", err)
		}
	}

	// recover in case sys ops panic
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occurred: %v, stack trace: %s", r, debug.Stack())
		}
	}()

	// Offline the checker must report any default that comes back, even the
	// pre-loss one; the baseline stays for the comparison.
	checkV4, checkV6 := baseline.V4, baseline.V6
	waitingForNetwork := false
	if given {
		if current, _ := readSnapshotFn(); !current.HasDefault() {
			waitingForNetwork = true
			checkV4, checkV6 = offlineCheckNextHops(baseline.V4, baseline.V6)
		}
	}

	event := make(chan struct{}, 1)
	var woke atomic.Bool
	// The checker must be gone before Listen returns: the next Listen starts a
	// new one, and two checkers on the same monitor must not overlap.
	checkCtx, stopCheck := context.WithCancel(ctx)
	var checker sync.WaitGroup
	checker.Add(1)
	defer func() {
		stopCheck()
		checker.Wait()
	}()
	go func() {
		defer checker.Done()
		nw.checkChanges(checkCtx, event, &woke, checkV4, checkV6)
	}()

	log.Infof("start watching for network changes")
	// debounce changes
	timer := time.NewTimer(0)
	timer.Stop()
	// A change that landed between two Listen rounds raised its event before
	// this checker subscribed: catch it by comparing with the baseline now.
	// While still offline there is nothing new to report, unless a default
	// came back meanwhile.
	if given {
		if current, _ := readSnapshotFn(); current.HasDefault() && (waitingForNetwork || classify(baseline, current) != ChangeNone) {
			timer.Reset(debounceTime)
		}
	}
	for {
		select {
		case <-event:
			timer.Reset(debounceTime)
		case <-timer.C:
			change := newChange(baseline)
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

// newChange compares the baseline with the current snapshot. A failed lookup
// leaves After empty, which classifies as ChangeOffline.
func newChange(before NextHops) Change {
	after, _ := readSnapshotFn()
	return Change{Kind: kindOf(before, after), Before: before, After: after}
}

// readSnapshot returns the current underlay snapshot. It fails only when
// neither family has a default next hop.
func readSnapshot() (NextHops, error) {
	var snapshot NextHops
	var err error
	snapshot.V4, snapshot.V6, err = readNextHops()
	snapshot.Addrs = defaultInterfaceAddrs(snapshot.V4, snapshot.V6)
	return snapshot, err
}

// defaultInterfaceAddrs collects the unicast addresses of the interfaces the
// default next hops leave through. Link-local addresses are skipped: they do
// not carry NetBird's connections and IPv6 ones churn on their own.
func defaultInterfaceAddrs(nexthops ...systemops.Nexthop) []netip.Addr {
	var addrs []netip.Addr
	seen := make(map[int]bool)
	for _, nh := range nexthops {
		if nh.Intf == nil || seen[nh.Intf.Index] {
			continue
		}
		seen[nh.Intf.Index] = true
		ifAddrs, err := nh.Intf.Addrs()
		if err != nil {
			log.Debugf("Network monitor: failed to read addresses of %s: %v", nh.Intf.Name, err)
			continue
		}
		for _, a := range ifAddrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			addr := prefix.Addr().Unmap()
			if addr.IsLinkLocalUnicast() || addr.IsLoopback() {
				continue
			}
			addrs = append(addrs, addr)
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addrs)
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
