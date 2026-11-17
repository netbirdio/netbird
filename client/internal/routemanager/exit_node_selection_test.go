package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

func newExitNodeTestManager() *DefaultManager {
	return &DefaultManager{routeSelector: routeselector.NewRouteSelector()}
}

func exitRoute(netID, peer string, skipAutoApply bool) *route.Route {
	return &route.Route{
		NetID:         route.NetID(netID),
		Network:       netip.MustParsePrefix("0.0.0.0/0"),
		Peer:          peer,
		SkipAutoApply: skipAutoApply,
	}
}

func TestPickPreferredExitNode(t *testing.T) {
	tests := []struct {
		name string
		info exitNodeInfo
		want route.NetID
	}{
		{
			name: "persisted user selection wins over management",
			info: exitNodeInfo{
				allIDs:               []route.NetID{"a", "b", "c"},
				userSelected:         []route.NetID{"b"},
				selectedByManagement: []route.NetID{"a"},
			},
			want: "b",
		},
		{
			name: "multiple user-selected self-heal to deterministic min",
			info: exitNodeInfo{
				allIDs:       []route.NetID{"a", "b", "c"},
				userSelected: []route.NetID{"c", "a"},
			},
			want: "a",
		},
		{
			name: "explicit opt-out keeps none",
			info: exitNodeInfo{
				allIDs:         []route.NetID{"a", "b"},
				userDeselected: []route.NetID{"a", "b"},
			},
			want: "",
		},
		{
			name: "fresh defaults to management auto-apply pick",
			info: exitNodeInfo{
				allIDs:               []route.NetID{"a", "b", "c"},
				selectedByManagement: []route.NetID{"b"},
			},
			want: "b",
		},
		{
			name: "no user pick and no management auto-apply selects none",
			info: exitNodeInfo{
				allIDs: []route.NetID{"c", "a", "b"},
			},
			want: "",
		},
		{
			name: "user-deselect does not block a management auto-apply sibling",
			info: exitNodeInfo{
				allIDs:               []route.NetID{"a", "b"},
				userDeselected:       []route.NetID{"a"},
				selectedByManagement: []route.NetID{"b"},
			},
			want: "b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pickPreferredExitNode(tt.info), "preferred exit node")
		})
	}
}

func TestEnforceSingleExitNode(t *testing.T) {
	m := newExitNodeTestManager()
	all := []route.NetID{"a", "b", "c"}

	m.enforceSingleExitNode("b", all)
	assert.False(t, m.routeSelector.IsSelected("a"), "a should be deselected")
	assert.True(t, m.routeSelector.IsSelected("b"), "b should be the only selected exit node")
	assert.False(t, m.routeSelector.IsSelected("c"), "c should be deselected")

	// Switching the preferred node moves the single selection.
	m.enforceSingleExitNode("c", all)
	assert.False(t, m.routeSelector.IsSelected("a"), "a stays deselected")
	assert.False(t, m.routeSelector.IsSelected("b"), "b should now be deselected")
	assert.True(t, m.routeSelector.IsSelected("c"), "c should now be selected")

	// Empty preferred turns every exit node off.
	m.enforceSingleExitNode("", all)
	for _, id := range all {
		assert.False(t, m.routeSelector.IsSelected(id), "no exit node should be selected")
	}
}

func TestEnforceSingleExitNode_RespectsDeselectAll(t *testing.T) {
	m := newExitNodeTestManager()
	m.routeSelector.DeselectAllRoutes()

	m.enforceSingleExitNode("b", []route.NetID{"a", "b"})

	assert.True(t, m.routeSelector.IsDeselectAll(), "global deselect-all must stay in effect")
	assert.False(t, m.routeSelector.IsSelected("b"), "no exit node should be forced on while deselect-all is set")
}

func TestUpdateRouteSelectorFromManagement_FreshSelectsOne(t *testing.T) {
	m := newExitNodeTestManager()
	routes := route.HAMap{
		"exitA|0.0.0.0/0":    {exitRoute("exitA", "p1", false)},
		"exitB|0.0.0.0/0":    {exitRoute("exitB", "p2", false)},
		"lan|192.168.1.0/24": {{NetID: "lan", Network: netip.MustParsePrefix("192.168.1.0/24"), Peer: "p3"}},
		"exitC|0.0.0.0/0":    {exitRoute("exitC", "p4", false)},
	}

	m.updateRouteSelectorFromManagement(routes)

	// Exactly one exit node (the deterministic first) is selected.
	assert.True(t, m.routeSelector.IsSelected("exitA"), "exitA is the deterministic default")
	assert.False(t, m.routeSelector.IsSelected("exitB"), "exitB must not also be selected")
	assert.False(t, m.routeSelector.IsSelected("exitC"), "exitC must not also be selected")
	// Non-exit routes are left at their default-on state.
	assert.True(t, m.routeSelector.IsSelected("lan"), "non-exit route selection is untouched")
}

func TestUpdateRouteSelectorFromManagement_HonorsPersistedPick(t *testing.T) {
	m := newExitNodeTestManager()
	routes := route.HAMap{
		"exitA|0.0.0.0/0": {exitRoute("exitA", "p1", false)},
		"exitB|0.0.0.0/0": {exitRoute("exitB", "p2", false)},
	}
	all := []route.NetID{"exitA", "exitB"}

	// Simulate the state the runtime select path leaves behind: exactly one
	// exit node explicitly selected, its sibling deselected.
	require.NoError(t, m.routeSelector.SelectRoutes([]route.NetID{"exitB"}, true, all))
	require.NoError(t, m.routeSelector.DeselectRoutes([]route.NetID{"exitA"}, all))

	m.updateRouteSelectorFromManagement(routes)

	assert.True(t, m.routeSelector.IsSelected("exitB"), "persisted pick must stay selected")
	assert.False(t, m.routeSelector.IsSelected("exitA"), "the other exit node stays deselected")
}

func TestUpdateRouteSelectorFromManagement_OptOutKeepsNone(t *testing.T) {
	m := newExitNodeTestManager()
	routes := route.HAMap{
		"exitA|0.0.0.0/0": {exitRoute("exitA", "p1", false)},
		"exitB|0.0.0.0/0": {exitRoute("exitB", "p2", false)},
	}
	all := []route.NetID{"exitA", "exitB"}

	// User deselected exit nodes and selected none.
	require.NoError(t, m.routeSelector.DeselectRoutes(all, all))

	m.updateRouteSelectorFromManagement(routes)

	assert.False(t, m.routeSelector.IsSelected("exitA"), "opt-out keeps exitA off")
	assert.False(t, m.routeSelector.IsSelected("exitB"), "opt-out keeps exitB off")
}

func TestUpdateRouteSelectorFromManagement_NoAutoApplySelectsNone(t *testing.T) {
	m := newExitNodeTestManager()
	// SkipAutoApply=true: management offers the exit nodes but doesn't request
	// auto-activation, so none should be selected until the user picks one.
	routes := route.HAMap{
		"exitA|0.0.0.0/0": {exitRoute("exitA", "p1", true)},
		"exitB|0.0.0.0/0": {exitRoute("exitB", "p2", true)},
	}

	m.updateRouteSelectorFromManagement(routes)

	assert.False(t, m.routeSelector.IsSelected("exitA"), "no auto-apply keeps exitA off")
	assert.False(t, m.routeSelector.IsSelected("exitB"), "no auto-apply keeps exitB off")
}
