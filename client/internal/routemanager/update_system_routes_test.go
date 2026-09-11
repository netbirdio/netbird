package routemanager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routemanager/client"
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

func TestUpdateSystemRoutesRetainsHandlerUntilRemoveSucceeds(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	handler := &removeRouteHandler{removeFailures: 1}
	m := &DefaultManager{activeRoutes: map[route.HAUniqueID]client.RouteHandler{id: handler}}

	require.Error(t, m.updateSystemRoutes(route.HAMap{}), "the first remove fails")
	assert.Contains(t, m.activeRoutes, id, "a failed remove must stay available for reconciliation")

	require.NoError(t, m.updateSystemRoutes(route.HAMap{}), "the next update retries the remove")
	assert.NotContains(t, m.activeRoutes, id, "the handler is removed after cleanup succeeds")
	assert.Equal(t, 2, handler.removeAttempts, "the handler must be called again")
}

func TestUpdateSystemRoutesRetainsHandlerAfterPersistentRemoveFailure(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	handler := &removeRouteHandler{removeFailures: -1}
	m := &DefaultManager{activeRoutes: map[route.HAUniqueID]client.RouteHandler{id: handler}}

	for range 2 {
		require.Error(t, m.updateSystemRoutes(route.HAMap{}), "a failed remove must keep the handler")
		assert.Contains(t, m.activeRoutes, id, "the handler must stay available for later reconciliation")
	}

	assert.Equal(t, 2, handler.removeAttempts, "every update must retry the handler cleanup")
}
