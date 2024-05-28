package routeselector_test

import (
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

			if tt.initialSelected != nil {
				err := rs.SelectRoutes(tt.initialSelected, false, allRoutes)
				require.NoError(t, err)
			}

			err := rs.SelectRoutes(tt.selectRoutes, tt.append, allRoutes)
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
	assert.False(t, rs.IsSelected("route4"))
}

func TestRouteSelector_FilterSelected(t *testing.T) {
	rs := routeselector.NewRouteSelector()

	err := rs.SelectRoutes([]route.NetID{"route1", "route2"}, false, []route.NetID{"route1", "route2", "route3"})
	require.NoError(t, err)

	routes := route.HAMap{
		"route1-10.0.0.0/8":     {},
		"route2-192.168.0.0/16": {},
		"route3-172.16.0.0/12":  {},
	}

	filtered := rs.FilterSelected(routes)

	assert.Equal(t, route.HAMap{
		"route1-10.0.0.0/8":     {},
		"route2-192.168.0.0/16": {},
	}, filtered)
}
