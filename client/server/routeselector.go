package server

import (
	"fmt"
	"slices"
)

type RouteSelector struct {
	selectedRoutes map[string]struct{}
	selectAll      bool
}

func NewRouteSelector() *RouteSelector {
	return &RouteSelector{
		selectedRoutes: map[string]struct{}{},
		// default selects all routes
		selectAll: true,
	}
}

// SelectRoutes updates the selected routes based on provided route IDs.
func (rs *RouteSelector) SelectRoutes(routes []string, append bool, allRoutes []string) error {
	if !append {
		rs.selectedRoutes = map[string]struct{}{}
	}
	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			return fmt.Errorf("route '%s' is not available", route)
		}

		rs.selectedRoutes[route] = struct{}{}
	}
	rs.selectAll = false
	return nil
}

// SelectAllRoutes sets the selector to select all routes.
func (rs *RouteSelector) SelectAllRoutes() {
	rs.selectAll = true
	rs.selectedRoutes = map[string]struct{}{}
}

// DeselectRoutes removes specific routes from the selection.
// If the selector is in "select all" mode, it will transition to "select specific" mode.
func (rs *RouteSelector) DeselectRoutes(routes []string, allRoutes []string) error {
	if rs.selectAll {
		rs.selectAll = false
		rs.selectedRoutes = map[string]struct{}{}
		for _, route := range allRoutes {
			rs.selectedRoutes[route] = struct{}{}
		}
	}

	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			return fmt.Errorf("route '%s' is not available", route)
		}
		delete(rs.selectedRoutes, route)
	}
	return nil
}

// DeselectAllRoutes deselects all routes, effectively disabling route selection.
func (rs *RouteSelector) DeselectAllRoutes() {
	rs.selectAll = false
	rs.selectedRoutes = map[string]struct{}{}
}

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID string) bool {
	if rs.selectAll {
		return true
	}
	_, selected := rs.selectedRoutes[routeID]
	return selected
}
