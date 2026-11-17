package routemanager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

func v6ExitRoute(netID, peer string) *route.Route {
	return &route.Route{
		NetID:   route.NetID(netID),
		Network: netip.MustParsePrefix("::/0"),
		Peer:    peer,
	}
}

func newSelectionTestManager() *DefaultManager {
	return &DefaultManager{
		routeSelector: routeselector.NewRouteSelector(),
		clientRoutes: route.HAMap{
			"exitA|0.0.0.0/0":    {exitRoute("exitA", "p1", true)},
			"exitA-v6|::/0":      {v6ExitRoute("exitA-v6", "p1")},
			"exitB|0.0.0.0/0":    {exitRoute("exitB", "p2", true)},
			"lan|192.168.1.0/24": {{NetID: "lan", Network: netip.MustParsePrefix("192.168.1.0/24"), Peer: "p3"}},
		},
	}
}

func TestSelectRoutes_ExitNodeExclusivity(t *testing.T) {
	m := newSelectionTestManager()

	// Selecting an exit node selects its v6 pair and deselects the sibling.
	require.NoError(t, m.selectRoutes([]route.NetID{"exitA"}, true))
	assert.True(t, m.routeSelector.IsSelected("exitA"), "exitA should be selected")
	assert.True(t, m.routeSelector.IsSelected("exitA-v6"), "the v6 pair follows its v4 base")
	assert.False(t, m.routeSelector.IsSelected("exitB"), "the sibling exit node must be deselected")

	// Switching to the sibling deselects the previous exit node and its v6 pair.
	require.NoError(t, m.selectRoutes([]route.NetID{"exitB"}, true))
	assert.True(t, m.routeSelector.IsSelected("exitB"), "exitB should now be selected")
	assert.False(t, m.routeSelector.IsSelected("exitA"), "the previous exit node must be deselected")
	assert.False(t, m.routeSelector.IsSelected("exitA-v6"), "the previous exit node's v6 pair must be deselected")
	assert.True(t, m.routeSelector.IsSelected("lan"), "non-exit route selection is untouched")

	// Selecting a non-exit route leaves the active exit node alone.
	require.NoError(t, m.selectRoutes([]route.NetID{"lan"}, true))
	assert.True(t, m.routeSelector.IsSelected("exitB"), "selecting a non-exit route keeps the exit node")

	// Deselecting the active exit node turns every exit node off.
	require.NoError(t, m.deselectRoutes([]route.NetID{"exitB"}))
	assert.False(t, m.routeSelector.IsSelected("exitB"), "exitB should be deselected")
	assert.False(t, m.routeSelector.IsSelected("exitA"), "exitA stays deselected")
	assert.True(t, m.routeSelector.IsSelected("lan"), "non-exit route selection is untouched")
}

func TestSelectRoutes_PartialErrorStillEnforcesExclusivity(t *testing.T) {
	// The unknown ID must be reported, but the valid exit node in the same
	// request is still selected — so its sibling must still be deselected.
	// Both orderings are covered: processing must continue past the invalid
	// ID wherever it sits in the request.
	requests := map[string][]route.NetID{
		"invalid id first": {"missing", "exitB"},
		"invalid id last":  {"exitB", "missing"},
	}

	for name, ids := range requests {
		t.Run(name, func(t *testing.T) {
			m := newSelectionTestManager()

			require.NoError(t, m.selectRoutes([]route.NetID{"exitA"}, true))

			err := m.selectRoutes(ids, true)
			assert.Error(t, err, "unknown id must be reported")
			assert.True(t, m.routeSelector.IsSelected("exitB"), "valid exit node from the request is selected")
			assert.False(t, m.routeSelector.IsSelected("exitA"), "sibling exit node must be deselected despite the error")
			assert.False(t, m.routeSelector.IsSelected("exitA-v6"), "sibling's v6 pair must be deselected too")
		})
	}
}

func TestSelectAllRoutes_KeepsSingleExitNode(t *testing.T) {
	// Both exit nodes are marked for auto-apply by management
	// (SkipAutoApply=false), the state where select-all could turn on two at
	// once without the immediate reconciliation.
	m := &DefaultManager{
		routeSelector: routeselector.NewRouteSelector(),
		clientRoutes: route.HAMap{
			"exitA|0.0.0.0/0":    {exitRoute("exitA", "p1", false)},
			"exitB|0.0.0.0/0":    {exitRoute("exitB", "p2", false)},
			"lan|192.168.1.0/24": {{NetID: "lan", Network: netip.MustParsePrefix("192.168.1.0/24"), Peer: "p3"}},
		},
	}

	require.NoError(t, m.selectRoutes([]route.NetID{"exitB"}, true))

	m.selectAllRoutes()

	assert.True(t, m.routeSelector.IsSelected("lan"), "non-exit routes are all selected")
	assert.True(t, m.routeSelector.IsSelected("exitA"), "the deterministic management pick stays active")
	assert.False(t, m.routeSelector.IsSelected("exitB"), "select-all must not leave a second exit node active")
}

func TestSelectRoutes_UnknownRoute(t *testing.T) {
	m := newSelectionTestManager()

	assert.Error(t, m.selectRoutes([]route.NetID{"missing"}, true), "selecting an unavailable route must fail")
	assert.Error(t, m.deselectRoutes([]route.NetID{"missing"}), "deselecting an unavailable route must fail")
}

// newPartialFailureTestManager exercises the real install/remove path without
// touching the system: the noop refcounter absorbs the route changes, and every
// route already has a watcher, so none is started.
func newPartialFailureTestManager() *DefaultManager {
	ctx := context.Background()

	m := &DefaultManager{
		ctx: ctx,
		clientRoutes: route.HAMap{
			"lan|192.168.1.0/24": {{NetID: "lan", Network: netip.MustParsePrefix("192.168.1.0/24"), Peer: "p1"}},
			"other|10.1.2.0/24":  {{NetID: "other", Network: netip.MustParsePrefix("10.1.2.0/24"), Peer: "p2"}},
		},
		routeSelector:  routeselector.NewRouteSelector(),
		notifier:       notifier.NewNotifier(),
		statusRecorder: peer.NewRecorder("https://mgm"),
		activeRoutes:   make(map[route.HAUniqueID]client.RouteHandler),
		clientNetworks: map[route.HAUniqueID]*client.Watcher{
			"lan|192.168.1.0/24": client.NewWatcher(client.WatcherConfig{Context: ctx}),
			"other|10.1.2.0/24":  client.NewWatcher(client.WatcherConfig{Context: ctx}),
		},
	}
	m.setupRefCounters(true)
	return m
}

// Regression for the reported symptom: a partial failure returned before
// TriggerSelection ran, so the valid route was marked selected while never
// reaching the routing table (activeRoutes/ip route).
func TestSelectRoutes_PartialFailureStillInstallsValidRoute(t *testing.T) {
	m := newPartialFailureTestManager()

	err := m.SelectRoutes([]route.NetID{"missing", "lan"}, false)

	assert.Error(t, err, "the unknown id must still be reported")
	assert.Contains(t, m.activeRoutes, route.HAUniqueID("lan|192.168.1.0/24"), "the valid route must be installed despite the error")
	assert.NotContains(t, m.activeRoutes, route.HAUniqueID("other|10.1.2.0/24"), "the deselected route must not be installed")
}

// Mirror of the case above: a partial failure must remove the valid route from
// the routing table, not just mark it deselected in the selector.
func TestDeselectRoutes_PartialFailureStillRemovesValidRoute(t *testing.T) {
	m := newPartialFailureTestManager()

	require.NoError(t, m.SelectRoutes([]route.NetID{"lan", "other"}, false))
	require.Contains(t, m.activeRoutes, route.HAUniqueID("lan|192.168.1.0/24"))
	require.Contains(t, m.activeRoutes, route.HAUniqueID("other|10.1.2.0/24"))

	err := m.DeselectRoutes([]route.NetID{"missing", "other"})

	assert.Error(t, err, "the unknown id must still be reported")
	assert.NotContains(t, m.activeRoutes, route.HAUniqueID("other|10.1.2.0/24"), "the deselected route must be removed")
	assert.Contains(t, m.activeRoutes, route.HAUniqueID("lan|192.168.1.0/24"), "the untouched route stays installed")
}

// The selection now runs on every request, including one where no ID is known
// and the selector stays untouched. Nothing may be torn down or reinstalled on
// that path.
func TestSelectRoutes_TotalFailureLeavesInstalledRoutesAlone(t *testing.T) {
	m := newPartialFailureTestManager()

	require.NoError(t, m.SelectRoutes([]route.NetID{"lan", "other"}, false))
	installed := maps.Keys(m.activeRoutes)

	err := m.SelectRoutes([]route.NetID{"missing"}, false)

	assert.Error(t, err, "the unknown id must still be reported")
	assert.ElementsMatch(t, installed, maps.Keys(m.activeRoutes), "a fully invalid request must not disturb the routing table")
}

func TestExitNodeSelectionHelpers(t *testing.T) {
	routesMap := map[route.NetID][]*route.Route{
		"exitA": {{Network: netip.MustParsePrefix("0.0.0.0/0")}},
		"exitB": {{Network: netip.MustParsePrefix("::/0")}},
		"lan":   {{Network: netip.MustParsePrefix("192.168.0.0/16")}},
	}

	assert.True(t, requestActivatesExitNode([]route.NetID{"exitA"}, routesMap), "v4 default route is an exit node")
	assert.True(t, requestActivatesExitNode([]route.NetID{"exitB"}, routesMap), "v6 default route is an exit node")
	assert.False(t, requestActivatesExitNode([]route.NetID{"lan"}, routesMap), "lan route is not an exit node")
	assert.False(t, requestActivatesExitNode([]route.NetID{"missing"}, routesMap), "unknown id is not an exit node")

	others := otherExitNodeIDs(routesMap, []route.NetID{"exitB"})
	assert.ElementsMatch(t, []route.NetID{"exitA"}, others, "only the other exit node is a sibling; the lan route is ignored")
}
