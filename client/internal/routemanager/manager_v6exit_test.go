package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

// TestUpdateRouteSelectorFromManagement_MirrorsV6ExitPair reproduces the bug seen
// in netbird-engine.log: persisted selector state has the v4 exit node deselected
// but its synthesized "-v6" pair explicitly selected (orphaned), so the ::/0 route
// leaked onto the tunnel. The management update must mirror the v4 deselect onto the
// v6 pair so FilterSelectedExitNodes drops it.
func TestUpdateRouteSelectorFromManagement_MirrorsV6ExitPair(t *testing.T) {
	const (
		v4ID = route.NetID("Exit Node (raspberrypi)")
		v6ID = route.NetID("Exit Node (raspberrypi)-v6")
	)
	all := []route.NetID{v4ID, v6ID}

	rs := routeselector.NewRouteSelector()
	// Orphan the v6 selection: select the pair, then deselect only the v4 base.
	require.NoError(t, rs.SelectRoutes([]route.NetID{v4ID, v6ID}, true, all))
	require.NoError(t, rs.DeselectRoutes([]route.NetID{v4ID}, all))
	require.True(t, rs.IsSelected(v6ID), "precondition: orphaned v6 selection survives v4 deselect")

	m := &DefaultManager{routeSelector: rs}

	v4Route := &route.Route{NetID: v4ID, Network: netip.MustParsePrefix("0.0.0.0/0")}
	v6Route := &route.Route{NetID: v6ID, Network: netip.MustParsePrefix("::/0")}
	clientRoutes := route.HAMap{
		"Exit Node (raspberrypi)|0.0.0.0/0": {v4Route},
		"Exit Node (raspberrypi)-v6|::/0":   {v6Route},
	}

	m.updateRouteSelectorFromManagement(clientRoutes)

	assert.False(t, rs.IsSelected(v6ID), "v6 pair must follow the v4 base deselect after the management update")

	filtered := rs.FilterSelectedExitNodes(clientRoutes)
	assert.Empty(t, filtered, "deselected v4 exit node must not leak its ::/0 pair onto the tunnel")
}
