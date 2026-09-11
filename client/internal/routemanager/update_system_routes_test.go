package routemanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type removeRouteHandler struct {
	removeFailures int
	removeAttempts int
}

type trackingDNSServer struct {
	*nbdns.MockServer
	beginCalls  int
	endCalls    int
	cancelCalls int
}

func (s *trackingDNSServer) BeginBatch()  { s.beginCalls++ }
func (s *trackingDNSServer) EndBatch()    { s.endCalls++ }
func (s *trackingDNSServer) CancelBatch() { s.cancelCalls++ }

func (h *removeRouteHandler) String() string                 { return "test route" }
func (h *removeRouteHandler) AddRoute(context.Context) error { return nil }
func (h *removeRouteHandler) AddAllowedIPs(string) error     { return nil }
func (h *removeRouteHandler) RemoveAllowedIPs() error        { return nil }
func (h *removeRouteHandler) RemoveRoute() error {
	h.removeAttempts++
	if h.removeFailures != 0 {
		if h.removeFailures > 0 {
			h.removeFailures--
		}
		return errors.New("remove route")
	}
	return nil
}

func TestUpdateSystemRoutesRetriesFailedRemovalWhileAbsent(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	handler := &removeRouteHandler{removeFailures: 1}
	m := newManagerWithActiveHandler(id, handler)

	require.Error(t, m.updateSystemRoutes(route.HAMap{}), "the first remove fails")
	assert.NotContains(t, m.activeRoutes, id, "a torn-down handler must not remain active")
	assert.Same(t, handler, m.pendingRemovals[id], "the failed removal must remain retryable")

	require.NoError(t, m.updateSystemRoutes(route.HAMap{}), "the next update retries the remove")
	assert.NotContains(t, m.pendingRemovals, id, "the pending removal must clear after cleanup succeeds")
	assert.Equal(t, 2, handler.removeAttempts, "the handler must be called again")
}

func TestUpdateSystemRoutesRecreatesDesiredRouteAfterPendingRemoval(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	handler := &removeRouteHandler{removeFailures: 1}
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
	handler := &removeRouteHandler{removeFailures: -1}
	m := newManagerWithActiveHandler(id, handler)
	desired := testRoute()

	require.Error(t, m.updateSystemRoutes(route.HAMap{}), "the first removal fails")
	require.Error(t, m.updateSystemRoutes(route.HAMap{id: {desired}}),
		"a desired route waits for its pending removal")
	assert.Empty(t, m.activeRoutes, "a replacement must not be created while cleanup is pending")
	assert.Same(t, handler, m.pendingRemovals[id], "only the original handler is pending")
	assert.Equal(t, 2, handler.removeAttempts, "every update retries the pending cleanup")
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
		pendingRemovals: map[route.HAUniqueID]client.RouteHandler{pendingID: &removeRouteHandler{removeFailures: -1}},
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
