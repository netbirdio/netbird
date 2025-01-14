package routeselector

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/errors"
	route "github.com/netbirdio/netbird/route"
)

type RouteSelector struct {
	mu             sync.RWMutex
	selectedRoutes map[route.NetID]struct{}
	selectAll      bool
}

func NewRouteSelector() *RouteSelector {
	return &RouteSelector{
		selectedRoutes: map[route.NetID]struct{}{},
		// default selects all routes
		selectAll: true,
	}
}

// SelectRoutes updates the selected routes based on the provided route IDs.
func (rs *RouteSelector) SelectRoutes(routes []route.NetID, appendRoute bool, allRoutes []route.NetID) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !appendRoute {
		rs.selectedRoutes = map[route.NetID]struct{}{}
	}

	var err *multierror.Error
	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			err = multierror.Append(err, fmt.Errorf("route '%s' is not available", route))
			continue
		}

		rs.selectedRoutes[route] = struct{}{}
	}
	rs.selectAll = false

	return errors.FormatErrorOrNil(err)
}

// SelectAllRoutes sets the selector to select all routes.
func (rs *RouteSelector) SelectAllRoutes() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.selectAll = true
	rs.selectedRoutes = map[route.NetID]struct{}{}
}

// DeselectRoutes removes specific routes from the selection.
// If the selector is in "select all" mode, it will transition to "select specific" mode.
func (rs *RouteSelector) DeselectRoutes(routes []route.NetID, allRoutes []route.NetID) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.selectAll {
		rs.selectAll = false
		rs.selectedRoutes = map[route.NetID]struct{}{}
		for _, route := range allRoutes {
			rs.selectedRoutes[route] = struct{}{}
		}
	}

	var err *multierror.Error

	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			err = multierror.Append(err, fmt.Errorf("route '%s' is not available", route))
			continue
		}
		delete(rs.selectedRoutes, route)
	}

	return errors.FormatErrorOrNil(err)
}

// DeselectAllRoutes deselects all routes, effectively disabling route selection.
func (rs *RouteSelector) DeselectAllRoutes() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.selectAll = false
	rs.selectedRoutes = map[route.NetID]struct{}{}
}

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.selectAll {
		return true
	}
	_, selected := rs.selectedRoutes[routeID]
	return selected
}

// FilterSelected removes unselected routes from the provided map.
func (rs *RouteSelector) FilterSelected(routes route.HAMap) route.HAMap {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.selectAll {
		return maps.Clone(routes)
	}

	filtered := route.HAMap{}
	for id, rt := range routes {
		if rs.IsSelected(id.NetID()) {
			filtered[id] = rt
		}
	}
	return filtered
}

// MarshalJSON implements the json.Marshaler interface
func (rs *RouteSelector) MarshalJSON() ([]byte, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return json.Marshal(struct {
		SelectedRoutes map[route.NetID]struct{} `json:"selected_routes"`
		SelectAll      bool                     `json:"select_all"`
	}{
		SelectAll:      rs.selectAll,
		SelectedRoutes: rs.selectedRoutes,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
// If the JSON is empty or null, it will initialize like a NewRouteSelector.
func (rs *RouteSelector) UnmarshalJSON(data []byte) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Check for null or empty JSON
	if len(data) == 0 || string(data) == "null" {
		rs.selectedRoutes = map[route.NetID]struct{}{}
		rs.selectAll = true
		return nil
	}

	var temp struct {
		SelectedRoutes map[route.NetID]struct{} `json:"selected_routes"`
		SelectAll      bool                     `json:"select_all"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	rs.selectedRoutes = temp.SelectedRoutes
	rs.selectAll = temp.SelectAll

	if rs.selectedRoutes == nil {
		rs.selectedRoutes = map[route.NetID]struct{}{}
	}

	return nil
}
