package routeselector

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/exp/maps"

	route "github.com/netbirdio/netbird/route"
)

type RouteSelector struct {
	selectedRoutes map[route.HAUniqueID]struct{}
	selectAll      bool
}

func NewRouteSelector() *RouteSelector {
	return &RouteSelector{
		selectedRoutes: map[route.HAUniqueID]struct{}{},
		// default selects all routes
		selectAll: true,
	}
}

// SelectRoutes updates the selected routes based on the provided route IDs.
func (rs *RouteSelector) SelectRoutes(routes []route.HAUniqueID, appendRoute bool, allRoutes []route.HAUniqueID) error {
	if !appendRoute {
		rs.selectedRoutes = map[route.HAUniqueID]struct{}{}
	}

	var multiErr *multierror.Error
	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			multiErr = multierror.Append(multiErr, fmt.Errorf("route '%s' is not available", route))
			continue
		}

		rs.selectedRoutes[route] = struct{}{}
	}
	rs.selectAll = false

	if multiErr != nil {
		multiErr.ErrorFormat = formatError
	}

	return multiErr.ErrorOrNil()
}

// SelectAllRoutes sets the selector to select all routes.
func (rs *RouteSelector) SelectAllRoutes() {
	rs.selectAll = true
	rs.selectedRoutes = map[route.HAUniqueID]struct{}{}
}

// DeselectRoutes removes specific routes from the selection.
// If the selector is in "select all" mode, it will transition to "select specific" mode.
func (rs *RouteSelector) DeselectRoutes(routes []route.HAUniqueID, allRoutes []route.HAUniqueID) error {
	if rs.selectAll {
		rs.selectAll = false
		rs.selectedRoutes = map[route.HAUniqueID]struct{}{}
		for _, route := range allRoutes {
			rs.selectedRoutes[route] = struct{}{}
		}
	}

	var multiErr *multierror.Error

	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			multiErr = multierror.Append(multiErr, fmt.Errorf("route '%s' is not available", route))
			continue
		}
		delete(rs.selectedRoutes, route)
	}

	if multiErr != nil {
		multiErr.ErrorFormat = formatError
	}

	return multiErr.ErrorOrNil()
}

// DeselectAllRoutes deselects all routes, effectively disabling route selection.
func (rs *RouteSelector) DeselectAllRoutes() {
	rs.selectAll = false
	rs.selectedRoutes = map[route.HAUniqueID]struct{}{}
}

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID route.HAUniqueID) bool {
	if rs.selectAll {
		return true
	}
	_, selected := rs.selectedRoutes[routeID]
	return selected
}

// FilterSelected removes unselected routes from the provided map.
func (rs *RouteSelector) FilterSelected(routes route.HAMap) route.HAMap {
	if rs.selectAll {
		return maps.Clone(routes)
	}

	filtered := route.HAMap{}
	for id, rt := range routes {
		netID := id
		if i := strings.LastIndex(string(id), "-"); i != -1 {
			netID = id[:i]
		}
		if rs.IsSelected(netID) {
			filtered[id] = rt
		}
	}
	return filtered
}

func formatError(es []error) string {
	if len(es) == 1 {
		return fmt.Sprintf("1 error occurred:\n\t* %s", es[0])
	}

	points := make([]string, len(es))
	for i, err := range es {
		points[i] = fmt.Sprintf("* %s", err)
	}

	return fmt.Sprintf(
		"%d errors occurred:\n\t%s",
		len(es), strings.Join(points, "\n\t"))
}
