package static_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/static"
	"github.com/netbirdio/netbird/route"
)

func TestRouteTeardownAfterAllowedIPRemovalFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		shared       bool
		persistent   bool
		routeFirst   bool
		routeFailure bool
	}{
		{name: "transient_failure"},
		{name: "persistent_failure", persistent: true},
		{name: "shared_same_peer", shared: true},
		{name: "transient_route_first", routeFirst: true},
		{name: "persistent_route_first", persistent: true, routeFirst: true},
		{name: "both_cleanup_errors", persistent: true, routeFirst: true, routeFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix("192.0.2.0/24")
			const peerKey = "routing-peer"
			installedRoutes := make(map[netip.Prefix]bool)
			installedAllowedIPs := make(map[netip.Prefix]string)
			removeErr := errors.New("simulated interface removal failure")
			routeErr := errors.New("simulated system route removal failure")
			removeAttempts := 0

			// Only the OS/interface boundary is simulated. Both counters and every
			// route handler below are the production implementations.
			routes := refcounter.New[netip.Prefix, struct{}, struct{}](
				func(key netip.Prefix, _ struct{}) (struct{}, error) {
					installedRoutes[key] = true
					return struct{}{}, nil
				},
				func(key netip.Prefix, _ struct{}) error {
					if tc.routeFailure {
						return routeErr
					}
					delete(installedRoutes, key)
					return nil
				},
			)
			allowedIPs := refcounter.NewAllowedIPs(
				func(key netip.Prefix, peer string) (string, error) {
					installedAllowedIPs[key] = peer
					return peer, nil
				},
				func(key netip.Prefix, _ string) error {
					removeAttempts++
					if tc.persistent || removeAttempts == 1 {
						return removeErr
					}
					delete(installedAllowedIPs, key)
					return nil
				},
			)
			newHandler := func() *static.Route {
				handler := static.NewRoute(common.HandlerParams{
					Route:                &route.Route{Network: prefix},
					RouteRefCounter:      routes,
					AllowedIPsRefCounter: allowedIPs,
				})
				require.NoError(t, handler.AddRoute(context.Background()))
				require.NoError(t, handler.AddAllowedIPs(peerKey))
				return handler
			}
			handler := newHandler()
			require.Equal(t, peerKey, installedAllowedIPs[prefix], "setup must install the allowed IP")

			// Cover both manager-first (main) and watcher-first teardown ordering.
			var firstErr error
			if tc.routeFirst {
				firstErr = handler.RemoveRoute()
			} else {
				firstErr = handler.RemoveAllowedIPs()
			}
			require.ErrorIs(t, firstErr, removeErr)
			if tc.routeFailure {
				assert.ErrorIs(t, firstErr, routeErr, "both cleanup errors must be returned")
			}
			if tc.routeFirst && !tc.routeFailure {
				assert.Empty(t, installedRoutes, "AllowedIP failure must not skip system route removal")
			}
			require.Equal(t, peerKey, installedAllowedIPs[prefix], "failed removal must leave the simulated allowed IP installed")
			if tc.shared {
				// Another owner acquires the same peer after the failed removal.
				// Retrying teardown must not decrement that owner's logical reference.
				survivor := newHandler()
				require.NoError(t, handler.RemoveRoute())
				assert.Equal(t, peerKey, installedAllowedIPs[prefix], "new owner must retain its installed allowed IP")
				assert.True(t, installedRoutes[prefix], "new owner must retain its installed route")
				require.NoError(t, survivor.RemoveAllowedIPs())
				require.NoError(t, survivor.RemoveRoute())
				assert.Empty(t, installedAllowedIPs, "last owner teardown must remove the installed allowed IP")
				assert.Empty(t, installedRoutes, "last owner teardown must remove the installed route")
				return
			}

			var err error
			if tc.routeFirst {
				err = handler.RemoveAllowedIPs()
			} else {
				err = handler.RemoveRoute()
			}
			if tc.persistent {
				assert.ErrorIs(t, err, removeErr, "teardown must report an allowed IP that still cannot be removed")
				assert.Equal(t, peerKey, installedAllowedIPs[prefix], "persistent interface failure must retain the installed allowed IP")
				if !tc.routeFailure {
					assert.Empty(t, installedRoutes, "persistent AllowedIP failure must not retain the installed system route")
				}
				return
			}
			assert.NoError(t, err)
			assert.Empty(t, installedRoutes, "teardown must remove the installed route")
			assert.Empty(t, installedAllowedIPs, "teardown must retry the failed allowed IP removal instead of leaking it")
		})
	}
}

// TestRouteConcurrentAllowedIPCleanup exercises manager teardown while a watcher
// installs or removes its peer. The race detector also checks peer-key access.
func TestRouteConcurrentAllowedIPCleanup(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	installed := make(map[netip.Prefix]string)
	allowedIPs := refcounter.NewAllowedIPs(
		func(key netip.Prefix, peer string) (string, error) { installed[key] = peer; return peer, nil },
		func(key netip.Prefix, _ string) error { delete(installed, key); return nil },
	)
	routes := refcounter.New[netip.Prefix, struct{}, struct{}](
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
		func(netip.Prefix, struct{}) error { return nil },
	)
	handler := static.NewRoute(common.HandlerParams{Route: &route.Route{Network: prefix}, RouteRefCounter: routes, AllowedIPsRefCounter: allowedIPs})
	for i := 0; i < 200; i++ {
		require.NoError(t, handler.AddRoute(context.Background()))
		start := make(chan struct{})
		errs := make(chan error, 3)
		var wg sync.WaitGroup
		for _, operation := range []func() error{
			func() error { return handler.AddAllowedIPs("routing-peer") },
			handler.RemoveAllowedIPs,
			handler.RemoveRoute,
		} {
			wg.Add(1)
			go func(operation func() error) { defer wg.Done(); <-start; errs <- operation() }(operation)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		// If the install won the race, the watcher still owns it until this release.
		require.NoError(t, handler.RemoveAllowedIPs())
		assert.Empty(t, installed, "final watcher release must remove any concurrent installation")
	}
}
