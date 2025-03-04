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

// Listen begins monitoring network changes. When a change is detected, this function will return without error.
func (nw *NetworkMonitor) Listen(ctx context.Context) (err error) {
	nw.mu.Lock()
	if nw.cancel != nil {
		nw.mu.Unlock()
		return errors.New("network monitor already started")
	}

	ctx, nw.cancel = context.WithCancel(ctx)
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

	if err := checkChange(ctx, nexthop4, nexthop6); err != nil {
		return err
	}

	// debounce changes
	select {
	case <-time.After(time.Second * 2):
		return
	case <-ctx.Done():
		return ctx.Err()
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
