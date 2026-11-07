package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

func useSecondary(t *testing.T) {
	t.Helper()
	inst, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	instance.SetCurrent(inst)
	t.Cleanup(func() { instance.SetCurrent(instance.Default()) })
}

func testRoutes() []*route.Route {
	return []*route.Route{
		{ID: "exit", NetID: "exit-node", Network: netip.MustParsePrefix("0.0.0.0/0"), Peer: "peerA"},
		{ID: "exit6", NetID: "exit-node-v6", Network: netip.MustParsePrefix("::/0"), Peer: "peerA"},
		{ID: "lan", NetID: "office", Network: netip.MustParsePrefix("192.168.77.0/24"), Peer: "peerB"},
	}
}

// T-COEX-U3: a secondary never plans a default route, and refuses a user's
// exit-node selection.
func TestSecondaryIgnoresExitNodes(t *testing.T) {
	useSecondary(t)
	m := &DefaultManager{routeSelector: routeselector.NewRouteSelector(), pubKey: "self"}

	_, clientRoutes := m.ClassifyRoutes(testRoutes())
	require.Len(t, clientRoutes, 1, "only the routed network is planned")
	for _, routes := range clientRoutes {
		for _, r := range routes {
			assert.NotZero(t, r.Network.Bits(), "no default route planned")
		}
	}

	err := m.secondary.checkSelection([]route.NetID{"exit-node"})
	require.Error(t, err)
	assert.Equal(t, "exit nodes are disabled in a secondary installation", err.Error(), "message")
	assert.NoError(t, m.secondary.checkSelection([]route.NetID{"office"}), "other networks can be selected")
}

func TestPrimaryKeepsExitNodes(t *testing.T) {
	m := &DefaultManager{routeSelector: routeselector.NewRouteSelector(), pubKey: "self"}
	_, clientRoutes := m.ClassifyRoutes(testRoutes())
	assert.Len(t, clientRoutes, 3, "the default installation keeps every route")
	assert.NoError(t, m.secondary.checkSelection([]route.NetID{"exit-node"}), "exit nodes can be selected")
}

func TestNewlyIdenticalReportsOnce(t *testing.T) {
	var s secondaryState
	p := netip.MustParsePrefix("192.168.77.0/24")
	assert.Equal(t, []netip.Prefix{p}, s.newlyIdentical([]netip.Prefix{p}), "first report")
	assert.Empty(t, s.newlyIdentical([]netip.Prefix{p}), "reported once")
}
