package routeselector_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

func TestRouteSelector_SelectRoutes(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.NetID

		selectRoutes []route.NetID
		append       bool

		wantSelected []route.NetID
		wantError    bool
	}{
		{
			name:         "Select specific routes, initial all selected",
			selectRoutes: []route.NetID{"route1", "route2"},
			wantSelected: []route.NetID{"route1", "route2"},
		},
		{
			name:            "Select specific routes, initial all deselected",
			initialSelected: []route.NetID{},
			selectRoutes:    []route.NetID{"route1", "route2"},
			wantSelected:    []route.NetID{"route1", "route2"},
		},
		{
			name:            "Select specific routes with initial selection",
			initialSelected: []route.NetID{"route1"},
			selectRoutes:    []route.NetID{"route2", "route3"},
			wantSelected:    []route.NetID{"route2", "route3"},
		},
		{
			name:         "Select non-existing route",
			selectRoutes: []route.NetID{"route1", "route4"},
			wantSelected: []route.NetID{"route1"},
			wantError:    true,
		},
		{
			name:            "Append route with initial selection",
			initialSelected: []route.NetID{"route1"},
			selectRoutes:    []route.NetID{"route2"},
			append:          true,
			wantSelected:    []route.NetID{"route1", "route2"},
		},
		{
			name:         "Append route without initial selection",
			selectRoutes: []route.NetID{"route2"},
			append:       true,
			wantSelected: []route.NetID{"route2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			err := rs.SelectRoutes(tt.initialSelected, false, allRoutes)
			require.NoError(t, err)

			err = rs.SelectRoutes(tt.selectRoutes, tt.append, allRoutes)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			for _, id := range allRoutes {
				assert.Equal(t, rs.IsSelected(id), slices.Contains(tt.wantSelected, id))
			}
		})
	}
}

func TestRouteSelector_SelectAllRoutes(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.NetID

		wantSelected []route.NetID
	}{
		{
			name:         "Initial all selected",
			wantSelected: []route.NetID{"route1", "route2", "route3"},
		},
		{
			name:            "Initial all deselected",
			initialSelected: []route.NetID{},
			wantSelected:    []route.NetID{"route1", "route2", "route3"},
		},
		{
			name:            "Initial some selected",
			initialSelected: []route.NetID{"route1"},
			wantSelected:    []route.NetID{"route1", "route2", "route3"},
		},
		{
			name:            "Initial all selected",
			initialSelected: []route.NetID{"route1", "route2", "route3"},
			wantSelected:    []route.NetID{"route1", "route2", "route3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			if tt.initialSelected != nil {
				err := rs.SelectRoutes(tt.initialSelected, false, allRoutes)
				require.NoError(t, err)
			}

			rs.SelectAllRoutes()

			for _, id := range allRoutes {
				assert.Equal(t, rs.IsSelected(id), slices.Contains(tt.wantSelected, id))
			}
		})
	}
}

func TestRouteSelector_DeselectRoutes(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.NetID

		deselectRoutes []route.NetID

		wantSelected []route.NetID
		wantError    bool
	}{
		{
			name:           "Deselect specific routes, initial all selected",
			deselectRoutes: []route.NetID{"route1", "route2"},
			wantSelected:   []route.NetID{"route3"},
		},
		{
			name:            "Deselect specific routes, initial all deselected",
			initialSelected: []route.NetID{},
			deselectRoutes:  []route.NetID{"route1", "route2"},
			wantSelected:    []route.NetID{},
		},
		{
			name:            "Deselect specific routes with initial selection",
			initialSelected: []route.NetID{"route1", "route2"},
			deselectRoutes:  []route.NetID{"route1", "route3"},
			wantSelected:    []route.NetID{"route2"},
		},
		{
			name:            "Deselect non-existing route",
			initialSelected: []route.NetID{"route1", "route2"},
			deselectRoutes:  []route.NetID{"route1", "route4"},
			wantSelected:    []route.NetID{"route2"},
			wantError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			if tt.initialSelected != nil {
				err := rs.SelectRoutes(tt.initialSelected, false, allRoutes)
				require.NoError(t, err)
			}

			err := rs.DeselectRoutes(tt.deselectRoutes, allRoutes)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			for _, id := range allRoutes {
				assert.Equal(t, rs.IsSelected(id), slices.Contains(tt.wantSelected, id))
			}
		})
	}
}

func TestRouteSelector_DeselectAll(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.NetID

		wantSelected []route.NetID
	}{
		{
			name:         "Initial all selected",
			wantSelected: []route.NetID{},
		},
		{
			name:            "Initial all deselected",
			initialSelected: []route.NetID{},
			wantSelected:    []route.NetID{},
		},
		{
			name:            "Initial some selected",
			initialSelected: []route.NetID{"route1", "route2"},
			wantSelected:    []route.NetID{},
		},
		{
			name:            "Initial all selected",
			initialSelected: []route.NetID{"route1", "route2", "route3"},
			wantSelected:    []route.NetID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			if tt.initialSelected != nil {
				err := rs.SelectRoutes(tt.initialSelected, false, allRoutes)
				require.NoError(t, err)
			}

			rs.DeselectAllRoutes()

			for _, id := range allRoutes {
				assert.Equal(t, rs.IsSelected(id), slices.Contains(tt.wantSelected, id))
			}
		})
	}
}

func TestRouteSelector_IsSelected(t *testing.T) {
	rs := routeselector.NewRouteSelector()

	err := rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, []route.NetID{"route1", "route2", "route3"})
	require.NoError(t, err)

	assert.True(t, rs.IsSelected("route1"))
	assert.True(t, rs.IsSelected("route2"))
	assert.False(t, rs.IsSelected("route3"))
	// Unknown route is selected by default
	assert.True(t, rs.IsSelected("route4"))
}

func TestRouteSelector_FilterSelected(t *testing.T) {
	rs := routeselector.NewRouteSelector()

	err := rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, []route.NetID{"route1", "route2", "route3"})
	require.NoError(t, err)

	routes := route.HAMap{
		"route1|10.0.0.0/8":     {},
		"route2|192.168.0.0/16": {},
		"route3|172.16.0.0/12":  {},
	}

	filtered := rs.FilterSelected(routes)

	assert.Equal(t, route.HAMap{
		"route1|10.0.0.0/8":     {},
		"route2|192.168.0.0/16": {},
	}, filtered)
}

func TestRouteSelector_FilterSelectedExitNodes(t *testing.T) {
	rs := routeselector.NewRouteSelector()

	// Create test routes
	exitNode1 := &route.Route{
		ID:            "route1",
		NetID:         "net1",
		Network:       netip.MustParsePrefix("0.0.0.0/0"),
		Peer:          "peer1",
		SkipAutoApply: false,
	}
	exitNode2 := &route.Route{
		ID:            "route2",
		NetID:         "net1",
		Network:       netip.MustParsePrefix("0.0.0.0/0"),
		Peer:          "peer2",
		SkipAutoApply: true,
	}
	normalRoute := &route.Route{
		ID:            "route3",
		NetID:         "net2",
		Network:       netip.MustParsePrefix("192.168.1.0/24"),
		Peer:          "peer3",
		SkipAutoApply: false,
	}

	routes := route.HAMap{
		"net1|0.0.0.0/0":      {exitNode1, exitNode2},
		"net2|192.168.1.0/24": {normalRoute},
	}

	// Test filtering
	filtered := rs.FilterSelectedExitNodes(routes)

	// Should only include selected exit nodes and all normal routes
	assert.Len(t, filtered, 2)
	assert.Len(t, filtered["net1|0.0.0.0/0"], 1) // Only the selected exit node
	assert.Equal(t, exitNode1.ID, filtered["net1|0.0.0.0/0"][0].ID)
	assert.Len(t, filtered["net2|192.168.1.0/24"], 1) // Normal route should be included
	assert.Equal(t, normalRoute.ID, filtered["net2|192.168.1.0/24"][0].ID)

	// Test with deselected routes
	err := rs.DeselectRoutes([]route.NetID{"net1"}, []route.NetID{"net1", "net2"})
	assert.NoError(t, err)
	filtered = rs.FilterSelectedExitNodes(routes)
	assert.Len(t, filtered, 1) // Only normal route should remain
	assert.Len(t, filtered["net2|192.168.1.0/24"], 1)
	assert.Equal(t, normalRoute.ID, filtered["net2|192.168.1.0/24"][0].ID)

	// Test with deselect all
	rs = routeselector.NewRouteSelector()
	rs.DeselectAllRoutes()
	filtered = rs.FilterSelectedExitNodes(routes)
	assert.Len(t, filtered, 0) // No routes should be selected
}

// TestRouteSelector_V6ExitPairSync covers SyncPairedSelection, which keeps a v4
// exit node and its synthesized "-v6" counterpart consistent. The selector itself
// is literal and never infers a v6 entry's state from its v4 base; callers that know
// the pairing (exit-node code paths) call SyncPairedSelection to force the v6 entry
// to follow the base, treating the pair as a single toggle.
func TestRouteSelector_V6ExitPairSync(t *testing.T) {
	all := []route.NetID{"exit1", "exit1-v6", "exit2", "exit2-v6", "corp", "corp-v6"}

	t.Run("selector lookups stay literal without sync", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		require.NoError(t, rs.DeselectRoutes([]route.NetID{"exit1"}, all))

		// The selector does not pair-resolve: the v6 entry is independent until synced.
		assert.False(t, rs.HasUserSelectionForRoute("exit1-v6"), "v6 entry has no state of its own")
		assert.True(t, rs.IsSelected("exit1-v6"), "unsynced v6 entry stays selected by default")

		// A route literally named "exit1-something" must never pair-resolve either.
		assert.False(t, rs.HasUserSelectionForRoute("exit1-something"))
	})

	t.Run("sync mirrors deselected v4 base onto v6", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		require.NoError(t, rs.DeselectRoutes([]route.NetID{"exit1"}, all))

		rs.SyncPairedSelection("exit1", "exit1-v6")

		assert.False(t, rs.IsSelected("exit1"))
		assert.False(t, rs.IsSelected("exit1-v6"), "v6 pair follows v4 base deselect")
		assert.True(t, rs.HasUserSelectionForRoute("exit1-v6"), "v6 carries explicit deselect after sync")
	})

	t.Run("sync mirrors selected v4 base onto v6", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		require.NoError(t, rs.SelectRoutes([]route.NetID{"exit1"}, false, all))

		rs.SyncPairedSelection("exit1", "exit1-v6")

		assert.True(t, rs.IsSelected("exit1"))
		assert.True(t, rs.IsSelected("exit1-v6"), "v6 pair follows v4 base select")
	})

	t.Run("sync clears v6 state when base has no explicit selection", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		require.NoError(t, rs.SelectRoutes([]route.NetID{"exit1-v6"}, true, all))
		require.True(t, rs.HasUserSelectionForRoute("exit1-v6"))

		rs.SyncPairedSelection("exit1", "exit1-v6")

		assert.False(t, rs.HasUserSelectionForRoute("exit1-v6"),
			"v6 explicit state is cleared so it follows management like its base")
	})

	// Regression for the observed bug (see netbird-engine.log): persisted state has
	// the v4 base deselected but the v6 sibling explicitly selected (orphaned). The
	// sync must reset the orphan so the ::/0 route does not leak onto the tunnel.
	t.Run("sync clears orphaned explicit v6 selection on deselected base", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()

		// Prior state: both explicitly selected, then only the v4 base deselected,
		// leaving the v6 entry as a stale explicit selection.
		require.NoError(t, rs.SelectRoutes([]route.NetID{"exit1", "exit1-v6"}, true, all))
		require.NoError(t, rs.DeselectRoutes([]route.NetID{"exit1"}, all))
		require.True(t, rs.IsSelected("exit1-v6"), "precondition: orphaned v6 selection")

		rs.SyncPairedSelection("exit1", "exit1-v6")

		assert.False(t, rs.IsSelected("exit1-v6"), "orphaned v6 selection reset to follow v4 deselect")

		v4Route := &route.Route{NetID: "exit1", Network: netip.MustParsePrefix("0.0.0.0/0")}
		v6Route := &route.Route{NetID: "exit1-v6", Network: netip.MustParsePrefix("::/0")}
		routes := route.HAMap{
			"exit1|0.0.0.0/0": {v4Route},
			"exit1-v6|::/0":   {v6Route},
		}
		filtered := rs.FilterSelectedExitNodes(routes)
		assert.Empty(t, filtered, "deselecting v4 base must drop the v6 pair even if it was explicitly selected before")
	})

	t.Run("filter drops synced v6 pair of deselected v4 base", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		require.NoError(t, rs.DeselectRoutes([]route.NetID{"exit1"}, all))
		rs.SyncPairedSelection("exit1", "exit1-v6")

		v4Route := &route.Route{NetID: "exit1", Network: netip.MustParsePrefix("0.0.0.0/0")}
		v6Route := &route.Route{NetID: "exit1-v6", Network: netip.MustParsePrefix("::/0")}
		routes := route.HAMap{
			"exit1|0.0.0.0/0": {v4Route},
			"exit1-v6|::/0":   {v6Route},
		}

		filtered := rs.FilterSelectedExitNodes(routes)
		assert.Empty(t, filtered, "deselecting v4 base must also drop the v6 pair")
	})

	t.Run("deselectAll makes sync a no-op", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		rs.DeselectAllRoutes()

		rs.SyncPairedSelection("exit1", "exit1-v6")

		assert.False(t, rs.HasUserSelectionForRoute("exit1-v6"), "sync must not write explicit state under deselectAll")
	})

	t.Run("non-exit *-v6 routes pass through FilterSelectedExitNodes", func(t *testing.T) {
		rs := routeselector.NewRouteSelector()
		require.NoError(t, rs.DeselectRoutes([]route.NetID{"corp"}, all))

		// A non-default-route entry named "corp-v6" is not an exit node and
		// must not be skipped because its v4 base "corp" is deselected.
		corpV6 := &route.Route{NetID: "corp-v6", Network: netip.MustParsePrefix("10.0.0.0/8")}
		routes := route.HAMap{
			"corp-v6|10.0.0.0/8": {corpV6},
		}

		filtered := rs.FilterSelectedExitNodes(routes)
		assert.Contains(t, filtered, route.HAUniqueID("corp-v6|10.0.0.0/8"),
			"non-exit *-v6 routes must not inherit unrelated v4 state in FilterSelectedExitNodes")
	})
}

// TestRouteSelector_SkipAutoApplyPerRoute verifies that management's
// SkipAutoApply flag governs each untouched route independently, even when
// the user has explicit selections on other routes.
func TestRouteSelector_SkipAutoApplyPerRoute(t *testing.T) {
	autoApplied := &route.Route{
		NetID:         "Auto",
		Network:       netip.MustParsePrefix("0.0.0.0/0"),
		SkipAutoApply: false,
	}
	skipApply := &route.Route{
		NetID:         "Skip",
		Network:       netip.MustParsePrefix("0.0.0.0/0"),
		SkipAutoApply: true,
	}
	routes := route.HAMap{
		"Auto|0.0.0.0/0": {autoApplied},
		"Skip|0.0.0.0/0": {skipApply},
	}

	rs := routeselector.NewRouteSelector()
	// User makes an unrelated explicit selection elsewhere.
	require.NoError(t, rs.DeselectRoutes([]route.NetID{"Unrelated"}, []route.NetID{"Auto", "Skip", "Unrelated"}))

	filtered := rs.FilterSelectedExitNodes(routes)
	assert.Contains(t, filtered, route.HAUniqueID("Auto|0.0.0.0/0"), "AutoApply route should be included")
	assert.NotContains(t, filtered, route.HAUniqueID("Skip|0.0.0.0/0"), "SkipAutoApply route should be excluded without explicit user selection")
}

// TestRouteSelector_V6ExitIsExitNode verifies that ::/0 routes are recognized
// as exit nodes by the selector's filter path.
func TestRouteSelector_V6ExitIsExitNode(t *testing.T) {
	v6Exit := &route.Route{
		NetID:         "V6Only",
		Network:       netip.MustParsePrefix("::/0"),
		SkipAutoApply: true,
	}
	routes := route.HAMap{
		"V6Only|::/0": {v6Exit},
	}

	rs := routeselector.NewRouteSelector()
	filtered := rs.FilterSelectedExitNodes(routes)
	assert.Empty(t, filtered, "::/0 should be treated as an exit node and respect SkipAutoApply")
}

func TestRouteSelector_NewRoutesBehavior(t *testing.T) {
	initialRoutes := []route.NetID{"route1", "route2", "route3"}
	newRoutes := []route.NetID{"route1", "route2", "route3", "route4", "route5"}

	tests := []struct {
		name            string
		initialState    func(rs *routeselector.RouteSelector) error // Setup initial state
		wantNewSelected []route.NetID                               // Expected selected routes after new routes appear
	}{
		{
			name: "New routes with initial selectAll state",
			initialState: func(rs *routeselector.RouteSelector) error {
				rs.SelectAllRoutes()
				return nil
			},
			// When selectAll is true, all routes including new ones should be selected
			wantNewSelected: []route.NetID{"route1", "route2", "route3", "route4", "route5"},
		},
		{
			name: "New routes after specific selection",
			initialState: func(rs *routeselector.RouteSelector) error {
				return rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, initialRoutes)
			},
			// When specific routes were selected, new routes should be selected
			wantNewSelected: []route.NetID{"route1", "route2", "route4", "route5"},
		},
		{
			name: "New routes after deselect all",
			initialState: func(rs *routeselector.RouteSelector) error {
				rs.DeselectAllRoutes()
				return nil
			},
			// After deselect all, new routes should remain unselected
			wantNewSelected: []route.NetID{},
		},
		{
			name: "New routes after deselecting specific routes",
			initialState: func(rs *routeselector.RouteSelector) error {
				rs.SelectAllRoutes()
				return rs.DeselectRoutes([]route.NetID{"route1"}, initialRoutes)
			},
			// After deselecting specific routes, new routes should be selected
			wantNewSelected: []route.NetID{"route2", "route3", "route4", "route5"},
		},
		{
			name: "New routes after selecting with append",
			initialState: func(rs *routeselector.RouteSelector) error {
				return rs.SelectRoutes([]route.NetID{"route1"}, true, initialRoutes)
			},
			// When routes were appended, new routes should be selected
			wantNewSelected: []route.NetID{"route1", "route2", "route3", "route4", "route5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			// Setup initial state
			err := tt.initialState(rs)
			require.NoError(t, err)

			// Verify selection state with new routes
			for _, id := range newRoutes {
				assert.Equal(t, rs.IsSelected(id), slices.Contains(tt.wantNewSelected, id),
					"Route %s selection state incorrect", id)
			}

			// Additional verification using FilterSelected
			routes := route.HAMap{
				"route1|10.0.0.0/8":     {},
				"route2|192.168.0.0/16": {},
				"route3|172.16.0.0/12":  {},
				"route4|10.10.0.0/16":   {},
				"route5|192.168.1.0/24": {},
			}

			filtered := rs.FilterSelected(routes)
			expectedLen := len(tt.wantNewSelected)
			assert.Equal(t, expectedLen, len(filtered),
				"FilterSelected returned wrong number of routes, got %d want %d", len(filtered), expectedLen)
		})
	}
}

func TestRouteSelector_MixedSelectionDeselection(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3"}

	tests := []struct {
		name              string
		routesToSelect    []route.NetID
		selectAppend      bool
		routesToDeselect  []route.NetID
		selectFirst       bool
		wantSelectedFinal []route.NetID
	}{
		{
			name:              "1. Select A, then Deselect B",
			routesToSelect:    []route.NetID{"route1"},
			selectAppend:      false,
			routesToDeselect:  []route.NetID{"route2"},
			selectFirst:       true,
			wantSelectedFinal: []route.NetID{"route1"},
		},
		{
			name:              "2. Select A, then Deselect A",
			routesToSelect:    []route.NetID{"route1"},
			selectAppend:      false,
			routesToDeselect:  []route.NetID{"route1"},
			selectFirst:       true,
			wantSelectedFinal: []route.NetID{},
		},
		{
			name:              "3. Deselect A (from all), then Select B",
			routesToSelect:    []route.NetID{"route2"},
			selectAppend:      false,
			routesToDeselect:  []route.NetID{"route1"},
			selectFirst:       false,
			wantSelectedFinal: []route.NetID{"route2"},
		},
		{
			name:              "4. Deselect A (from all), then Select A",
			routesToSelect:    []route.NetID{"route1"},
			selectAppend:      false,
			routesToDeselect:  []route.NetID{"route1"},
			selectFirst:       false,
			wantSelectedFinal: []route.NetID{"route1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			var err1, err2 error

			if tt.selectFirst {
				err1 = rs.SelectRoutes(tt.routesToSelect, tt.selectAppend, allRoutes)
				require.NoError(t, err1)
				err2 = rs.DeselectRoutes(tt.routesToDeselect, allRoutes)
				require.NoError(t, err2)
			} else {
				err1 = rs.DeselectRoutes(tt.routesToDeselect, allRoutes)
				require.NoError(t, err1)
				err2 = rs.SelectRoutes(tt.routesToSelect, tt.selectAppend, allRoutes)
				require.NoError(t, err2)
			}

			for _, r := range allRoutes {
				assert.Equal(t, slices.Contains(tt.wantSelectedFinal, r), rs.IsSelected(r), "Route %s final state mismatch", r)
			}
		})
	}
}

func TestRouteSelector_AfterDeselectAll(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3"}

	tests := []struct {
		name          string
		initialAction func(rs *routeselector.RouteSelector) error
		secondAction  func(rs *routeselector.RouteSelector) error
		wantSelected  []route.NetID
		wantError     bool
	}{
		{
			name: "Deselect all -> select specific routes",
			initialAction: func(rs *routeselector.RouteSelector) error {
				rs.DeselectAllRoutes()
				return nil
			},
			secondAction: func(rs *routeselector.RouteSelector) error {
				return rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, allRoutes)
			},
			wantSelected: []route.NetID{"route1", "route2"},
		},
		{
			name: "Deselect all -> select with append",
			initialAction: func(rs *routeselector.RouteSelector) error {
				rs.DeselectAllRoutes()
				return nil
			},
			secondAction: func(rs *routeselector.RouteSelector) error {
				return rs.SelectRoutes([]route.NetID{"route1"}, true, allRoutes)
			},
			wantSelected: []route.NetID{"route1"},
		},
		{
			name: "Deselect all -> deselect specific",
			initialAction: func(rs *routeselector.RouteSelector) error {
				rs.DeselectAllRoutes()
				return nil
			},
			secondAction: func(rs *routeselector.RouteSelector) error {
				return rs.DeselectRoutes([]route.NetID{"route1"}, allRoutes)
			},
			wantSelected: []route.NetID{},
		},
		{
			name: "Deselect all -> select all",
			initialAction: func(rs *routeselector.RouteSelector) error {
				rs.DeselectAllRoutes()
				return nil
			},
			secondAction: func(rs *routeselector.RouteSelector) error {
				rs.SelectAllRoutes()
				return nil
			},
			wantSelected: []route.NetID{"route1", "route2", "route3"},
		},
		{
			name: "Deselect all -> deselect non-existent route",
			initialAction: func(rs *routeselector.RouteSelector) error {
				rs.DeselectAllRoutes()
				return nil
			},
			secondAction: func(rs *routeselector.RouteSelector) error {
				return rs.DeselectRoutes([]route.NetID{"route4"}, allRoutes)
			},
			wantSelected: []route.NetID{},
			wantError:    false,
		},
		{
			name: "Select specific -> deselect all -> select different",
			initialAction: func(rs *routeselector.RouteSelector) error {
				err := rs.SelectRoutes([]route.NetID{"route1"}, false, allRoutes)
				if err != nil {
					return err
				}
				rs.DeselectAllRoutes()
				return nil
			},
			secondAction: func(rs *routeselector.RouteSelector) error {
				return rs.SelectRoutes([]route.NetID{"route2", "route3"}, false, allRoutes)
			},
			wantSelected: []route.NetID{"route2", "route3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			err := tt.initialAction(rs)
			require.NoError(t, err)

			err = tt.secondAction(rs)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			for _, id := range allRoutes {
				expected := slices.Contains(tt.wantSelected, id)
				assert.Equal(t, expected, rs.IsSelected(id),
					"Route %s selection state incorrect, expected %v", id, expected)
			}

			routes := route.HAMap{
				"route1|10.0.0.0/8":     {},
				"route2|192.168.0.0/16": {},
				"route3|172.16.0.0/12":  {},
			}

			filtered := rs.FilterSelected(routes)
			assert.Equal(t, len(tt.wantSelected), len(filtered),
				"FilterSelected returned wrong number of routes")
		})
	}
}

func TestRouteSelector_ComplexScenarios(t *testing.T) {
	allRoutes := []route.NetID{"route1", "route2", "route3", "route4"}

	tests := []struct {
		name         string
		actions      []func(rs *routeselector.RouteSelector) error
		wantSelected []route.NetID
	}{
		{
			name: "Select all -> deselect specific -> select different with append",
			actions: []func(rs *routeselector.RouteSelector) error{
				func(rs *routeselector.RouteSelector) error {
					rs.SelectAllRoutes()
					return nil
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.DeselectRoutes([]route.NetID{"route1", "route2"}, allRoutes)
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.SelectRoutes([]route.NetID{"route1"}, true, allRoutes)
				},
			},
			wantSelected: []route.NetID{"route1", "route3", "route4"},
		},
		{
			name: "Deselect all -> select specific -> deselect one -> select different with append",
			actions: []func(rs *routeselector.RouteSelector) error{
				func(rs *routeselector.RouteSelector) error {
					rs.DeselectAllRoutes()
					return nil
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, allRoutes)
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.DeselectRoutes([]route.NetID{"route2"}, allRoutes)
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.SelectRoutes([]route.NetID{"route3"}, true, allRoutes)
				},
			},
			wantSelected: []route.NetID{"route1", "route3"},
		},
		{
			name: "Select specific -> deselect specific -> select all -> deselect different",
			actions: []func(rs *routeselector.RouteSelector) error{
				func(rs *routeselector.RouteSelector) error {
					return rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, allRoutes)
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.DeselectRoutes([]route.NetID{"route2"}, allRoutes)
				},
				func(rs *routeselector.RouteSelector) error {
					rs.SelectAllRoutes()
					return nil
				},
				func(rs *routeselector.RouteSelector) error {
					return rs.DeselectRoutes([]route.NetID{"route3", "route4"}, allRoutes)
				},
			},
			wantSelected: []route.NetID{"route1", "route2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := routeselector.NewRouteSelector()

			for i, action := range tt.actions {
				err := action(rs)
				require.NoError(t, err, "Action %d failed", i)
			}

			for _, id := range allRoutes {
				expected := slices.Contains(tt.wantSelected, id)
				assert.Equal(t, expected, rs.IsSelected(id),
					"Route %s selection state incorrect", id)
			}

			routes := route.HAMap{
				"route1|10.0.0.0/8":     {},
				"route2|192.168.0.0/16": {},
				"route3|172.16.0.0/12":  {},
				"route4|10.10.0.0/16":   {},
			}

			filtered := rs.FilterSelected(routes)
			assert.Equal(t, len(tt.wantSelected), len(filtered),
				"FilterSelected returned wrong number of routes")
		})
	}
}

// TestRouteSelector_EnableExitNodeKeepsOtherRoutes is a regression test for the
// tray exit-node toggle disabling every non-exit routed network. The tray used
// to Select an exit node with append=false, which the RouteSelector treats as
// "drop the whole current selection" (default-on semantics) — so enabling an
// exit node also turned off every LAN/route the user had on. The fix sends
// append=true and lets the daemon's SelectNetworks handler deselect only the
// sibling exit nodes. This test models that handler sequence against the
// selector: SelectRoutes(exit, append=true) followed by DeselectRoutes(other
// exit nodes) must leave non-exit routes untouched.
func TestRouteSelector_EnableExitNodeKeepsOtherRoutes(t *testing.T) {
	rs := routeselector.NewRouteSelector()
	all := []route.NetID{"exitA", "exitB", "lan1", "lan2"}

	// User has two LAN routes on (default-on: nothing deselected => all selected).
	require.True(t, rs.IsSelected("lan1"))
	require.True(t, rs.IsSelected("lan2"))

	// Tray enables exitA: SelectNetworks handler does SelectRoutes(append=true)
	// then deselects sibling exit nodes (exitB), never the LAN routes.
	require.NoError(t, rs.SelectRoutes([]route.NetID{"exitA"}, true, all))
	require.NoError(t, rs.DeselectRoutes([]route.NetID{"exitB"}, all))

	assert.True(t, rs.IsSelected("exitA"), "selected exit node stays on")
	assert.False(t, rs.IsSelected("exitB"), "sibling exit node is deselected")
	assert.True(t, rs.IsSelected("lan1"), "non-exit route must stay selected")
	assert.True(t, rs.IsSelected("lan2"), "non-exit route must stay selected")
}
