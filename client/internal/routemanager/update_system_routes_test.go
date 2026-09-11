package routemanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type removeRouteHandler struct {
	removeFailures int
	removeAttempts int
}

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
