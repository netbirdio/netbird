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
	allRoutes := []string{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []string

		selectRoutes []string
		append       bool

		wantSelected []string
		wantError    bool
	}{
		{
			name:         "Select specific routes, initial all selected",
			selectRoutes: []string{"route1", "route2"},
			wantSelected: []string{"route1", "route2"},
		},
		{
			name:            "Select specific routes, initial all deselected",
			initialSelected: []string{},
			selectRoutes:    []string{"route1", "route2"},
			wantSelected:    []string{"route1", "route2"},
		},
		{
			name:            "Select specific routes with initial selection",
			initialSelected: []string{"route1"},
			selectRoutes:    []string{"route2", "route3"},
			wantSelected:    []string{"route2", "route3"},
		},
		{
			name:         "Select non-existing route",
			selectRoutes: []string{"route1", "route4"},
			wantSelected: []string{"route1"},
			wantError:    true,
		},
		{
			name:            "Append route with initial selection",
			initialSelected: []string{"route1"},
			selectRoutes:    []string{"route2"},
			append:          true,
			wantSelected:    []string{"route1", "route2"},
		},
		{
			name:         "Append route without initial selection",
			selectRoutes: []string{"route2"},
			append:       true,
			wantSelected: []string{"route2"},
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
	allRoutes := []string{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []string

		wantSelected []string
	}{
		{
			name:         "Initial all selected",
			wantSelected: []string{"route1", "route2", "route3"},
		},
		{
			name:            "Initial all deselected",
			initialSelected: []string{},
			wantSelected:    []string{"route1", "route2", "route3"},
		},
		{
			name:            "Initial some selected",
			initialSelected: []string{"route1"},
			wantSelected:    []string{"route1", "route2", "route3"},
		},
		{
			name:            "Initial all selected",
			initialSelected: []string{"route1", "route2", "route3"},
			wantSelected:    []string{"route1", "route2", "route3"},
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

func TestRouteSelector_DeelectRoutes(t *testing.T) {
	allRoutes := []string{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []string

		deselectRoutes []string

		wantSelected []string
		wantError    bool
	}{
		{
			name:           "Deselect specific routes, initial all selected",
			deselectRoutes: []string{"route1", "route2"},
			wantSelected:   []string{"route3"},
		},
		{
			name:            "Deselect specific routes, initial all deselected",
			initialSelected: []string{},
			deselectRoutes:  []string{"route1", "route2"},
			wantSelected:    []string{},
		},
		{
			name:            "Deselect specific routes with initial selection",
			initialSelected: []string{"route1", "route2"},
			deselectRoutes:  []string{"route1", "route3"},
			wantSelected:    []string{"route2"},
		},
		{
			name:            "Deselect non-existing route",
			initialSelected: []string{"route1", "route2"},
			deselectRoutes:  []string{"route1", "route4"},
			wantSelected:    []string{"route2"},
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
	allRoutes := []string{"route1", "route2", "route3"}

	tests := []struct {
		name            string
		initialSelected []string

		wantSelected []string
	}{
		{
			name:         "Initial all selected",
			wantSelected: []string{},
		},
		{
			name:            "Initial all deselected",
			initialSelected: []string{},
			wantSelected:    []string{},
		},
		{
			name:            "Initial some selected",
			initialSelected: []string{"route1", "route2"},
			wantSelected:    []string{},
		},
		{
			name:            "Initial all selected",
			initialSelected: []string{"route1", "route2", "route3"},
			wantSelected:    []string{},
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

	err := rs.SelectRoutes([]string{"route1", "route2"}, false, []string{"route1", "route2", "route3"})
	require.NoError(t, err)

	assert.True(t, rs.IsSelected("route1"))
	assert.True(t, rs.IsSelected("route2"))
	assert.False(t, rs.IsSelected("route3"))
	assert.False(t, rs.IsSelected("route4"))
}

func TestRouteSelector_FilterSelected(t *testing.T) {
	rs := routeselector.NewRouteSelector()

	err := rs.SelectRoutes([]string{"route1", "route2"}, false, []string{"route1", "route2", "route3"})
	require.NoError(t, err)

	routes := map[string][]*route.Route{
		"route1": {},
		"route2": {},
		"route3": {},
	}

	filtered := rs.FilterSelected(routes)

	assert.Equal(t, map[string][]*route.Route{
		"route1": {},
		"route2": {},
	}, filtered)
}
