package routemanager

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/dynamic"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type trackingDNSServer struct {
	*nbdns.MockServer
	beginCalls  int
	endCalls    int
	cancelCalls int
}

func (s *trackingDNSServer) BeginBatch()  { s.beginCalls++ }
func (s *trackingDNSServer) EndBatch()    { s.endCalls++ }
func (s *trackingDNSServer) CancelBatch() { s.cancelCalls++ }

func TestUpdateSystemRoutesRetriesFailedRemovalWhileAbsent(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	cleanup := newCleanupFailure(1)
	handler := newDynamicCleanupHandler(t, cleanup, nil)
	m := newManagerWithActiveHandler(id, handler)

	require.Error(t, m.updateSystemRoutes(route.HAMap{}), "the first remove fails")
	assert.NotContains(t, m.activeRoutes, id, "a torn-down handler must not remain active")
	assert.Same(t, handler, m.pendingRemovals[id], "the failed removal must remain retryable")

	require.NoError(t, m.updateSystemRoutes(route.HAMap{}), "the next update retries the remove")
	assert.NotContains(t, m.pendingRemovals, id, "the pending removal must clear after cleanup succeeds")
	assert.Equal(t, 2, int(cleanup.attempts.Load()), "the handler must be called again")
}

func TestUpdateSystemRoutesRecreatesDesiredRouteAfterPendingRemoval(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	cleanup := newCleanupFailure(1)
	handler := newDynamicCleanupHandler(t, cleanup, nil)
	m := newManagerWithActiveHandler(id, handler)
	desired := testRoute()

	require.Error(t, m.updateSystemRoutes(route.HAMap{}), "the first remove fails")
	require.NoError(t, m.updateSystemRoutes(route.HAMap{id: {desired}}),
		"a desired route is recreated after its pending removal succeeds")
	assert.NotContains(t, m.pendingRemovals, id, "cleanup completed before recreation")
	assert.Contains(t, m.activeRoutes, id, "the desired route must become active again")
	assert.NotSame(t, handler, m.activeRoutes[id], "the torn-down handler must not be reused")
}

func TestUpdateSystemRoutesDoesNotDuplicateRouteAfterPersistentRemovalFailure(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	cleanup := newCleanupFailure(-1)
	handler := newDynamicCleanupHandler(t, cleanup, nil)
	m := newManagerWithActiveHandler(id, handler)
	desired := testRoute()

	require.Error(t, m.updateSystemRoutes(route.HAMap{}), "the first removal fails")
	require.Error(t, m.updateSystemRoutes(route.HAMap{id: {desired}}),
		"a desired route waits for its pending removal")
	assert.Empty(t, m.activeRoutes, "a replacement must not be created while cleanup is pending")
	assert.Same(t, handler, m.pendingRemovals[id], "only the original handler is pending")
	assert.Equal(t, 2, int(cleanup.attempts.Load()), "every update retries the pending cleanup")
}

func TestUpdateSystemRoutesCommitsDNSBatchWhenPendingRemovalFails(t *testing.T) {
	pendingID := route.HAUniqueID("old||10.0.0.0/24")
	desiredID := route.HAUniqueID("new||dns.example.com")
	registered := 0
	dnsServer := &trackingDNSServer{MockServer: &nbdns.MockServer{
		RegisterHandlerFunc: func(domain.List, dns.Handler, int) { registered++ },
	}}
	m := &DefaultManager{
		ctx:             context.Background(),
		activeRoutes:    map[route.HAUniqueID]client.RouteHandler{},
		pendingRemovals: map[route.HAUniqueID]client.RouteHandler{pendingID: newDynamicCleanupHandler(t, newCleanupFailure(-1), nil)},
		dnsServer:       dnsServer,
		useNewDNSRoute:  true,
		routeRefCounter: refcounter.New(
			func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
			func(netip.Prefix, struct{}) error { return nil },
		),
	}
	desired := &route.Route{
		NetworkType: route.DomainNetwork,
		Domains:     domain.List{domain.Domain("dns.example.com")},
	}

	require.Error(t, m.updateSystemRoutes(route.HAMap{desiredID: {desired}}),
		"the unrelated pending removal still fails")
	assert.Contains(t, m.activeRoutes, desiredID, "the unrelated DNS route must be active")
	assert.Equal(t, 1, registered, "the DNS handler must be registered")
	assert.Equal(t, 1, dnsServer.beginCalls, "the DNS batch must start once")
	assert.Equal(t, 1, dnsServer.endCalls, "the DNS batch must commit successful work")
	assert.Zero(t, dnsServer.cancelCalls, "the DNS batch must not discard successful work")
}

func TestObsoleteWatcherCleanupHandoff(t *testing.T) {
	testCases := []struct {
		name                string
		removeFailures      int
		firstUpdateFails    bool
		expectedRemoveCalls int
	}{
		{
			name:                "transient failure retries in the same update",
			removeFailures:      1,
			expectedRemoveCalls: 2,
		},
		{
			name:                "persistent failure moves to pending removal",
			removeFailures:      2,
			firstUpdateFails:    true,
			expectedRemoveCalls: 3,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			id := route.HAUniqueID("net1||10.0.0.0/24")
			cleanup := newCleanupFailure(int32(testCase.removeFailures))
			handler := newDynamicCleanupHandler(t, nil, cleanup)
			m := newManagerWithActiveHandler(id, handler)
			m.clientNetworks = map[route.HAUniqueID]*client.Watcher{id: startedWatcher(t, handler)}

			m.stopObsoleteClients(route.HAMap{})
			require.Equal(t, 1, int(cleanup.attempts.Load()), "Watcher.Stop makes the first cleanup attempt")
			assert.Empty(t, m.clientNetworks, "the obsolete watcher must be removed")

			err := m.updateSystemRoutes(route.HAMap{})
			if testCase.firstUpdateFails {
				require.Error(t, err, "the second cleanup attempt fails")
				assert.Empty(t, m.activeRoutes, "a failed teardown must not remain active")
				assert.Same(t, handler, m.pendingRemovals[id], "the handler must remain pending")
				require.NoError(t, m.updateSystemRoutes(route.HAMap{}), "the third cleanup attempt succeeds")
			} else {
				require.NoError(t, err, "RemoveRoute retries the cleanup in the same route update")
			}

			assert.Empty(t, m.activeRoutes, "the removed handler must not remain active")
			assert.Empty(t, m.pendingRemovals, "successful cleanup must clear pending state")
			require.NoError(t, handler.RemoveAllowedIPs(), "successful cleanup must not retain pending references")
			assert.Equal(t, testCase.expectedRemoveCalls, int(cleanup.attempts.Load()),
				"Stop and manager updates must make the expected cleanup attempts")
		})
	}
}

func newManagerWithActiveHandler(id route.HAUniqueID, handler client.RouteHandler) *DefaultManager {
	return &DefaultManager{
		ctx:          context.Background(),
		activeRoutes: map[route.HAUniqueID]client.RouteHandler{id: handler},
		routeRefCounter: refcounter.New(
			func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
			func(netip.Prefix, struct{}) error { return nil },
		),
	}
}

func testRoute() *route.Route {
	return &route.Route{Network: netip.MustParsePrefix("10.0.0.0/24")}
}

func startedWatcher(t *testing.T, handler client.RouteHandler) *client.Watcher {
	t.Helper()

	statusRecorder := peer.NewRecorder("https://mgm")
	require.NoError(t, statusRecorder.AddPeer("peer", "peer", "100.64.0.1", ""))
	w := client.NewWatcher(client.WatcherConfig{
		Context:        context.Background(),
		StatusRecorder: statusRecorder,
		Handler:        handler,
	})
	t.Cleanup(w.Stop)
	go w.Start()
	w.SendUpdate(client.RoutesUpdate{Routes: []*route.Route{{ID: "route", Peer: "peer"}}})
	require.Eventually(t, func() bool { return len(statusRecorder.GetActiveRoutePeers()) == 1 },
		time.Second, time.Millisecond, "the watcher must add allowed IPs")
	return w
}

type cleanupFailure struct {
	remaining atomic.Int32
	attempts  atomic.Int32
}

func newCleanupFailure(count int32) *cleanupFailure {
	failure := &cleanupFailure{}
	failure.remaining.Store(count)
	return failure
}

func (f *cleanupFailure) remove(netip.Prefix) error {
	if f == nil {
		return nil
	}
	f.attempts.Add(1)
	if remaining := f.remaining.Load(); remaining != 0 {
		if remaining > 0 {
			f.remaining.Add(-1)
		}
		return errors.New("remove prefix")
	}
	return nil
}

func newDynamicCleanupHandler(t *testing.T, routeFailure, allowedFailure *cleanupFailure) *dynamic.Route {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	recorder := peer.NewRecorder("https://mgm")
	handler := dynamic.NewRoute(common.HandlerParams{
		Route: &route.Route{
			ID: "cleanup:1", NetworkType: route.DomainNetwork,
			// An IP literal exercises the real resolver without external DNS queries.
			Domains: domain.List{"203.0.113.7"},
		},
		DnsRouterInterval: time.Hour,
		StatusRecorder:    recorder,
		RouteRefCounter: refcounter.New(
			func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
			func(prefix netip.Prefix, _ struct{}) error { return routeFailure.remove(prefix) }),
		AllowedIPsRefCounter: refcounter.NewAllowedIPs(
			func(_ netip.Prefix, peerKey string) (string, error) { return peerKey, nil },
			func(prefix netip.Prefix, _ string) error { return allowedFailure.remove(prefix) }),
	}, netip.AddrPort{})
	t.Cleanup(func() {
		cancel()
		for _, failure := range []*cleanupFailure{routeFailure, allowedFailure} {
			if failure != nil {
				failure.remaining.Store(0)
			}
		}
		require.NoError(t, handler.RemoveRoute())
	})
	require.NoError(t, handler.AddRoute(ctx))
	require.Eventually(t, func() bool { return len(recorder.GetResolvedDomainsStates()) == 1 },
		time.Second, time.Millisecond, "the real dynamic handler must resolve its prefix")
	return handler
}
