package routeselector

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/route"
)

type RouteSelector struct {
	mu             sync.RWMutex
	selectedRoutes map[route.NetID]struct{}
	selectAll      bool

	// Indicates if new routes should be automatically selected
	includeNewRoutes bool

	// All known routes at the time of deselection
	knownRoutes []route.NetID
}

func NewRouteSelector() *RouteSelector {
	return &RouteSelector{
		selectedRoutes:   map[route.NetID]struct{}{},
		selectAll:        true,
		includeNewRoutes: false,
		knownRoutes:      []route.NetID{},
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
	rs.includeNewRoutes = appendRoute

	return errors.FormatErrorOrNil(err)
}

// SelectAllRoutes sets the selector to select all routes.
func (rs *RouteSelector) SelectAllRoutes() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.selectAll = true
	rs.selectedRoutes = map[route.NetID]struct{}{}
	rs.includeNewRoutes = false
}

// DeselectRoutes removes specific routes from the selection.
// If the selector is in "select all" mode, it will transition to "select specific" mode
// but will keep new routes selected.
func (rs *RouteSelector) DeselectRoutes(routes []route.NetID, allRoutes []route.NetID) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.selectAll {
		rs.selectAll = false
		rs.includeNewRoutes = true
		rs.knownRoutes = make([]route.NetID, len(allRoutes))
		copy(rs.knownRoutes, allRoutes)

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
	rs.includeNewRoutes = false
	rs.selectedRoutes = map[route.NetID]struct{}{}
}

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.selectAll {
		return true
	}

	// Check if the route exists in selectedRoutes
	_, selected := rs.selectedRoutes[routeID]
	if selected {
		return true
	}

	// If includeNewRoutes is true and this is a new route (not in knownRoutes),
	// then it should be selected
	if rs.includeNewRoutes && !slices.Contains(rs.knownRoutes, routeID) {
		return true
	}

	return false
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
		netID := id.NetID()
		_, selected := rs.selectedRoutes[netID]

		// Include if directly selected or if it's a new route and includeNewRoutes is true
		if selected || (rs.includeNewRoutes && !slices.Contains(rs.knownRoutes, netID)) {
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
		SelectedRoutes   map[route.NetID]struct{} `json:"selected_routes"`
		SelectAll        bool                     `json:"select_all"`
		IncludeNewRoutes bool                     `json:"include_new_routes"`
		KnownRoutes      []route.NetID            `json:"known_routes"`
	}{
		SelectAll:        rs.selectAll,
		SelectedRoutes:   rs.selectedRoutes,
		IncludeNewRoutes: rs.includeNewRoutes,
		KnownRoutes:      rs.knownRoutes,
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
		rs.includeNewRoutes = false
		rs.knownRoutes = []route.NetID{}
		return nil
	}

	var temp struct {
		SelectedRoutes   map[route.NetID]struct{} `json:"selected_routes"`
		SelectAll        bool                     `json:"select_all"`
		IncludeNewRoutes bool                     `json:"include_new_routes"`
		KnownRoutes      []route.NetID            `json:"known_routes"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	rs.selectedRoutes = temp.SelectedRoutes
	rs.selectAll = temp.SelectAll
	rs.includeNewRoutes = temp.IncludeNewRoutes
	rs.knownRoutes = temp.KnownRoutes

	if rs.selectedRoutes == nil {
		rs.selectedRoutes = map[route.NetID]struct{}{}
	}
	if rs.knownRoutes == nil {
		rs.knownRoutes = []route.NetID{}
	}

	return nil
}
