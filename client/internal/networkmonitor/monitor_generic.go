//go:build !ios && !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager"
)

// Start begins monitoring network changes. When a change is detected, it calls the callback asynchronously and returns.
func (nw *NetworkMonitor) Start(ctx context.Context, callback func()) (err error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	nw.mu.Lock()
	ctx, nw.cancel = context.WithCancel(ctx)
	nw.mu.Unlock()

	nw.wg.Add(1)
	defer nw.wg.Done()

	var nexthop4, nexthop6 netip.Addr
	var intf4, intf6 *net.Interface

	operation := func() error {
		var errv4, errv6 error
		nexthop4, intf4, errv4 = routemanager.GetNextHop(netip.IPv4Unspecified())
		nexthop6, intf6, errv6 = routemanager.GetNextHop(netip.IPv6Unspecified())

		if errv4 != nil && errv6 != nil {
			return errors.New("failed to get default next hops")
		}

		if errv4 == nil {
			log.Debugf("Network monitor: IPv4 default route: %s, interface: %s", nexthop4, intf4.Name)
		}
		if errv6 == nil {
			log.Debugf("Network monitor: IPv6 default route: %s, interface: %s", nexthop6, intf6.Name)
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
			err = fmt.Errorf("panic occurred: %v, stack trace: %s", r, string(debug.Stack()))
		}
	}()

	if err := checkChange(ctx, nexthop4, intf4, nexthop6, intf6, callback); err != nil {
		return fmt.Errorf("check change: %w", err)
	}

	return nil
}

// Stop stops the network monitor.
func (nw *NetworkMonitor) Stop() {
	nw.mu.Lock()
	defer nw.mu.Unlock()

	if nw.cancel != nil {
		nw.cancel()
		nw.wg.Wait()
	}
}
