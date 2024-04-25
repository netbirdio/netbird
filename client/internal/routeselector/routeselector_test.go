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
	allRoutes := []route.HAUniqueID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.HAUniqueID

		selectRoutes []route.HAUniqueID
		append       bool

		wantSelected []route.HAUniqueID
		wantError    bool
	}{
		{
			name:         "Select specific routes, initial all selected",
			selectRoutes: []route.HAUniqueID{"route1", "route2"},
			wantSelected: []route.HAUniqueID{"route1", "route2"},
		},
		{
			name:            "Select specific routes, initial all deselected",
			initialSelected: []route.HAUniqueID{},
			selectRoutes:    []route.HAUniqueID{"route1", "route2"},
			wantSelected:    []route.HAUniqueID{"route1", "route2"},
		},
		{
			name:            "Select specific routes with initial selection",
			initialSelected: []route.HAUniqueID{"route1"},
			selectRoutes:    []route.HAUniqueID{"route2", "route3"},
			wantSelected:    []route.HAUniqueID{"route2", "route3"},
		},
		{
			name:         "Select non-existing route",
			selectRoutes: []route.HAUniqueID{"route1", "route4"},
			wantSelected: []route.HAUniqueID{"route1"},
			wantError:    true,
		},
		{
			name:            "Append route with initial selection",
			initialSelected: []route.HAUniqueID{"route1"},
			selectRoutes:    []route.HAUniqueID{"route2"},
			append:          true,
			wantSelected:    []route.HAUniqueID{"route1", "route2"},
		},
		{
			name:         "Append route without initial selection",
			selectRoutes: []route.HAUniqueID{"route2"},
			append:       true,
			wantSelected: []route.HAUniqueID{"route2"},
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
	allRoutes := []route.HAUniqueID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.HAUniqueID

		wantSelected []route.HAUniqueID
	}{
		{
			name:         "Initial all selected",
			wantSelected: []route.HAUniqueID{"route1", "route2", "route3"},
		},
		{
			name:            "Initial all deselected",
			initialSelected: []route.HAUniqueID{},
			wantSelected:    []route.HAUniqueID{"route1", "route2", "route3"},
		},
		{
			name:            "Initial some selected",
			initialSelected: []route.HAUniqueID{"route1"},
			wantSelected:    []route.HAUniqueID{"route1", "route2", "route3"},
		},
		{
			name:            "Initial all selected",
			initialSelected: []route.HAUniqueID{"route1", "route2", "route3"},
			wantSelected:    []route.HAUniqueID{"route1", "route2", "route3"},
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
	allRoutes := []route.HAUniqueID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.HAUniqueID

		deselectRoutes []route.HAUniqueID

		wantSelected []route.HAUniqueID
		wantError    bool
	}{
		{
			name:           "Deselect specific routes, initial all selected",
			deselectRoutes: []route.HAUniqueID{"route1", "route2"},
			wantSelected:   []route.HAUniqueID{"route3"},
		},
		{
			name:            "Deselect specific routes, initial all deselected",
			initialSelected: []route.HAUniqueID{},
			deselectRoutes:  []route.HAUniqueID{"route1", "route2"},
			wantSelected:    []route.HAUniqueID{},
		},
		{
			name:            "Deselect specific routes with initial selection",
			initialSelected: []route.HAUniqueID{"route1", "route2"},
			deselectRoutes:  []route.HAUniqueID{"route1", "route3"},
			wantSelected:    []route.HAUniqueID{"route2"},
		},
		{
			name:            "Deselect non-existing route",
			initialSelected: []route.HAUniqueID{"route1", "route2"},
			deselectRoutes:  []route.HAUniqueID{"route1", "route4"},
			wantSelected:    []route.HAUniqueID{"route2"},
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
	allRoutes := []route.HAUniqueID{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []route.HAUniqueID

		wantSelected []route.HAUniqueID
	}{
		{
			name:         "Initial all selected",
			wantSelected: []route.HAUniqueID{},
		},
		{
			name:            "Initial all deselected",
			initialSelected: []route.HAUniqueID{},
			wantSelected:    []route.HAUniqueID{},
		},
		{
			name:            "Initial some selected",
			initialSelected: []route.HAUniqueID{"route1", "route2"},
			wantSelected:    []route.HAUniqueID{},
		},
		{
			name:            "Initial all selected",
			initialSelected: []route.HAUniqueID{"route1", "route2", "route3"},
			wantSelected:    []route.HAUniqueID{},
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

	err := rs.SelectRoutes([]route.HAUniqueID{"route1", "route2"}, false, []route.HAUniqueID{"route1", "route2", "route3"})
	require.NoError(t, err)

	assert.True(t, rs.IsSelected("route1"))
	assert.True(t, rs.IsSelected("route2"))
	assert.False(t, rs.IsSelected("route3"))
	assert.False(t, rs.IsSelected("route4"))
}

func TestRouteSelector_FilterSelected(t *testing.T) {
	rs := routeselector.NewRouteSelector()

	err := rs.SelectRoutes([]route.HAUniqueID{"route1", "route2"}, false, []route.HAUniqueID{"route1", "route2", "route3"})
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
