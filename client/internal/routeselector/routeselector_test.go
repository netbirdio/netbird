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
		ID:         "route1",
		NetID:      "net1",
		Network:    netip.MustParsePrefix("0.0.0.0/0"),
		Peer:       "peer1",
		IsSelected: true,
	}
	exitNode2 := &route.Route{
		ID:         "route2",
		NetID:      "net1",
		Network:    netip.MustParsePrefix("0.0.0.0/0"),
		Peer:       "peer2",
		IsSelected: false,
	}
	normalRoute := &route.Route{
		ID:         "route3",
		NetID:      "net2",
		Network:    netip.MustParsePrefix("192.168.1.0/24"),
		Peer:       "peer3",
		IsSelected: true,
	}

	// Create route map
	routes := route.HAMap{
		"ha1": {exitNode1, exitNode2}, // Multiple exit nodes for same HA group
		"ha2": {normalRoute},          // Normal route
	}

	// Test filtering
	filtered := rs.FilterSelectedExitNodes(routes)

	// Should only include selected exit nodes and all normal routes
	assert.Len(t, filtered, 2)
	assert.Len(t, filtered["ha1"], 1) // Only the selected exit node
	assert.Equal(t, exitNode1.ID, filtered["ha1"][0].ID)
	assert.Len(t, filtered["ha2"], 1) // Normal route should be included
	assert.Equal(t, normalRoute.ID, filtered["ha2"][0].ID)

	// Test with deselected routes
	rs.DeselectRoutes([]route.NetID{"net1"}, []route.NetID{"net1", "net2"})
	filtered = rs.FilterSelectedExitNodes(routes)
	assert.Len(t, filtered, 1) // Only normal route should remain
	assert.Len(t, filtered["ha2"], 1)
	assert.Equal(t, normalRoute.ID, filtered["ha2"][0].ID)

	// Test with deselect all
	rs = routeselector.NewRouteSelector()
	rs.DeselectAllRoutes()
	filtered = rs.FilterSelectedExitNodes(routes)
	assert.Len(t, filtered, 0) // No routes should be selected
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
