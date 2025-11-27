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

const (
	exitNodeCIDR = "0.0.0.0/0"
)

type RouteSelector struct {
	mu               sync.RWMutex
	deselectedRoutes map[route.NetID]struct{}
	selectedRoutes   map[route.NetID]struct{}
	deselectAll      bool
}

func NewRouteSelector() *RouteSelector {
	return &RouteSelector{
		deselectedRoutes: map[route.NetID]struct{}{},
		selectedRoutes:   map[route.NetID]struct{}{},
		deselectAll:      false,
	}
}

// SelectRoutes updates the selected routes based on the provided route IDs.
func (rs *RouteSelector) SelectRoutes(routes []route.NetID, appendRoute bool, allRoutes []route.NetID) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if !appendRoute || rs.deselectAll {
		if rs.deselectedRoutes == nil {
			rs.deselectedRoutes = map[route.NetID]struct{}{}
		}
		if rs.selectedRoutes == nil {
			rs.selectedRoutes = map[route.NetID]struct{}{}
		}
		maps.Clear(rs.deselectedRoutes)
		maps.Clear(rs.selectedRoutes)
		for _, r := range allRoutes {
			rs.deselectedRoutes[r] = struct{}{}
		}
	}

	var err *multierror.Error
	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			err = multierror.Append(err, fmt.Errorf("route '%s' is not available", route))
			continue
		}
		delete(rs.deselectedRoutes, route)
		rs.selectedRoutes[route] = struct{}{}
	}

	rs.deselectAll = false

	return errors.FormatErrorOrNil(err)
}

// SelectAllRoutes sets the selector to select all routes.
func (rs *RouteSelector) SelectAllRoutes() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.deselectAll = false
	if rs.deselectedRoutes == nil {
		rs.deselectedRoutes = map[route.NetID]struct{}{}
	}
	if rs.selectedRoutes == nil {
		rs.selectedRoutes = map[route.NetID]struct{}{}
	}
	maps.Clear(rs.deselectedRoutes)
	maps.Clear(rs.selectedRoutes)
}

// DeselectRoutes removes specific routes from the selection.
func (rs *RouteSelector) DeselectRoutes(routes []route.NetID, allRoutes []route.NetID) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.deselectAll {
		return nil
	}

	var err *multierror.Error
	for _, route := range routes {
		if !slices.Contains(allRoutes, route) {
			err = multierror.Append(err, fmt.Errorf("route '%s' is not available", route))
			continue
		}
		rs.deselectedRoutes[route] = struct{}{}
		delete(rs.selectedRoutes, route)
	}

	return errors.FormatErrorOrNil(err)
}

// DeselectAllRoutes deselects all routes, effectively disabling route selection.
func (rs *RouteSelector) DeselectAllRoutes() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.deselectAll = true
	if rs.deselectedRoutes == nil {
		rs.deselectedRoutes = map[route.NetID]struct{}{}
	}
	if rs.selectedRoutes == nil {
		rs.selectedRoutes = map[route.NetID]struct{}{}
	}
	maps.Clear(rs.deselectedRoutes)
	maps.Clear(rs.selectedRoutes)
}

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.deselectAll {
		return false
	}

	_, deselected := rs.deselectedRoutes[routeID]
	isSelected := !deselected
	return isSelected
}

// FilterSelected removes unselected routes from the provided map.
func (rs *RouteSelector) FilterSelected(routes route.HAMap) route.HAMap {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.deselectAll {
		return route.HAMap{}
	}

	filtered := route.HAMap{}
	for id, rt := range routes {
		netID := id.NetID()
		_, deselected := rs.deselectedRoutes[netID]
		if !deselected {
			filtered[id] = rt
		}
	}
	return filtered
}

// HasUserSelectionForRoute returns true if the user has explicitly selected or deselected this specific route
func (rs *RouteSelector) HasUserSelectionForRoute(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	_, selected := rs.selectedRoutes[routeID]
	_, deselected := rs.deselectedRoutes[routeID]
	return selected || deselected
}

func (rs *RouteSelector) FilterSelectedExitNodes(routes route.HAMap) route.HAMap {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.deselectAll {
		return route.HAMap{}
	}

	filtered := make(route.HAMap, len(routes))
	for id, rt := range routes {
		netID := id.NetID()
		if rs.isDeselected(netID) {
			continue
		}

		if !isExitNode(rt) {
			filtered[id] = rt
			continue
		}

		rs.applyExitNodeFilter(id, netID, rt, filtered)
	}

	return filtered
}

func (rs *RouteSelector) isDeselected(netID route.NetID) bool {
	_, deselected := rs.deselectedRoutes[netID]
	return deselected || rs.deselectAll
}

func isExitNode(rt []*route.Route) bool {
	return len(rt) > 0 && rt[0].Network.String() == exitNodeCIDR
}

func (rs *RouteSelector) applyExitNodeFilter(
	id route.HAUniqueID,
	netID route.NetID,
	rt []*route.Route,
	out route.HAMap,
) {

	if rs.hasUserSelections() {
		// user made explicit selects/deselects
		if rs.IsSelected(netID) {
			out[id] = rt
		}
		return
	}

	// no explicit selections: only include routes marked !SkipAutoApply (=AutoApply)
	sel := collectSelected(rt)
	if len(sel) > 0 {
		out[id] = sel
	}
}

func (rs *RouteSelector) hasUserSelections() bool {
	return len(rs.selectedRoutes) > 0 || len(rs.deselectedRoutes) > 0
}

func collectSelected(rt []*route.Route) []*route.Route {
	var sel []*route.Route
	for _, r := range rt {
		if !r.SkipAutoApply {
			sel = append(sel, r)
		}
	}
	return sel
}

// MarshalJSON implements the json.Marshaler interface
func (rs *RouteSelector) MarshalJSON() ([]byte, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return json.Marshal(struct {
		SelectedRoutes   map[route.NetID]struct{} `json:"selected_routes"`
		DeselectedRoutes map[route.NetID]struct{} `json:"deselected_routes"`
		DeselectAll      bool                     `json:"deselect_all"`
	}{
		SelectedRoutes:   rs.selectedRoutes,
		DeselectedRoutes: rs.deselectedRoutes,
		DeselectAll:      rs.deselectAll,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
// If the JSON is empty or null, it will initialize like a NewRouteSelector.
func (rs *RouteSelector) UnmarshalJSON(data []byte) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Check for null or empty JSON
	if len(data) == 0 || string(data) == "null" {
		rs.deselectedRoutes = map[route.NetID]struct{}{}
		rs.selectedRoutes = map[route.NetID]struct{}{}
		rs.deselectAll = false
		return nil
	}

	var temp struct {
		SelectedRoutes   map[route.NetID]struct{} `json:"selected_routes"`
		DeselectedRoutes map[route.NetID]struct{} `json:"deselected_routes"`
		DeselectAll      bool                     `json:"deselect_all"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	rs.selectedRoutes = temp.SelectedRoutes
	rs.deselectedRoutes = temp.DeselectedRoutes
	rs.deselectAll = temp.DeselectAll

	if rs.deselectedRoutes == nil {
		rs.deselectedRoutes = map[route.NetID]struct{}{}
	}
	if rs.selectedRoutes == nil {
		rs.selectedRoutes = map[route.NetID]struct{}{}
	}

	return nil
}
