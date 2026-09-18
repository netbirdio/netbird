package routemanager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/route"
)

// updateClientNetworks no longer stops obsolete watchers itself. That moved to the
// caller, which must stop them before updateSystemRoutes so a dynamic route releases
// its allowed IPs before its state is wiped. Only the move is pinned here.
func TestUpdateClientNetworksDoesNotStopObsoleteClients(t *testing.T) {
	id := route.HAUniqueID("net1||10.0.0.0/24")
	watcher := client.NewWatcher(client.WatcherConfig{Context: context.Background()})

	m := &DefaultManager{
		clientNetworks: map[route.HAUniqueID]*client.Watcher{
			id: watcher,
		},
		activeRoutes: map[route.HAUniqueID]client.RouteHandler{},
	}

	// networks no longer contains id, but updateClientNetworks must not touch it.
	m.updateClientNetworks(1, route.HAMap{})

	assert.Contains(t, m.clientNetworks, id, "updateClientNetworks must leave obsolete watchers for the caller to stop")

	m.stopObsoleteClients(route.HAMap{})

	assert.NotContains(t, m.clientNetworks, id, "stopObsoleteClients must remove the obsolete watcher")
}
