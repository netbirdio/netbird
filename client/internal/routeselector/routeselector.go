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

// SelectRoutes updates the selected routes based on the provided route IDs.
func (rs *RouteSelector) SelectRoutes(routes []string, appendRoute bool, allRoutes []string) error {
	if !appendRoute {
		rs.selectedRoutes = map[string]struct{}{}
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

// FilterSelected removes unselected routes from the provided map.
func (rs *RouteSelector) FilterSelected(routes map[string][]*route.Route) map[string][]*route.Route {
	if rs.selectAll {
		return maps.Clone(routes)
	}

	filtered := map[string][]*route.Route{}
	for id, rt := range routes {
		if rs.IsSelected(id) {
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
