package routeselector

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/route"
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
		clear(rs.deselectedRoutes)
		clear(rs.selectedRoutes)
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
	clear(rs.deselectedRoutes)
	clear(rs.selectedRoutes)
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
	clear(rs.deselectedRoutes)
	clear(rs.selectedRoutes)
}

// IsDeselectAll reports whether the global "deselect all" flag is set, i.e. the
// user explicitly disabled every route. Callers enforcing per-route invariants
// (e.g. single exit node) should leave the selection untouched when it is.
func (rs *RouteSelector) IsDeselectAll() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return rs.deselectAll
}

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return rs.isSelectedLocked(routeID)
}

// SyncPairedSelection forces pairedID's explicit selection state to match baseID's,
// so a synthesized "-v6" exit route always follows its v4 base: selecting or
// deselecting the v4 exit node governs the ::/0 pair, and any stale (orphaned)
// explicit state on the v6 entry is reset. The v4/v6 exit pair is treated as a single
// toggle, so the v6 entry carries no independent selection of its own.
func (rs *RouteSelector) SyncPairedSelection(baseID, pairedID route.NetID) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.deselectAll {
		return
	}

	_, baseSelected := rs.selectedRoutes[baseID]
	_, baseDeselected := rs.deselectedRoutes[baseID]

	delete(rs.selectedRoutes, pairedID)
	delete(rs.deselectedRoutes, pairedID)

	switch {
	case baseSelected:
		rs.selectedRoutes[pairedID] = struct{}{}
	case baseDeselected:
		rs.deselectedRoutes[pairedID] = struct{}{}
	}
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
		if !rs.isDeselectedLocked(id.NetID()) {
			filtered[id] = rt
		}
	}
	return filtered
}

// HasUserSelectionForRoute returns true if the user has explicitly selected or deselected this route.
// The lookup is literal; v4/v6 exit pairs are kept consistent at write time via SyncPairedSelection,
// so a synthesized "-v6" entry carries the same explicit state as its v4 base.
func (rs *RouteSelector) HasUserSelectionForRoute(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return rs.hasUserSelectionForRouteLocked(routeID)
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
		if rs.isDeselectedLocked(netID) {
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

func (rs *RouteSelector) isSelectedLocked(routeID route.NetID) bool {
	if rs.deselectAll {
		return false
	}
	_, deselected := rs.deselectedRoutes[routeID]
	return !deselected
}

func (rs *RouteSelector) isDeselectedLocked(netID route.NetID) bool {
	if rs.deselectAll {
		return true
	}
	_, deselected := rs.deselectedRoutes[netID]
	return deselected
}

func (rs *RouteSelector) hasUserSelectionForRouteLocked(routeID route.NetID) bool {
	_, selected := rs.selectedRoutes[routeID]
	_, deselected := rs.deselectedRoutes[routeID]
	return selected || deselected
}

func (rs *RouteSelector) applyExitNodeFilter(
	id route.HAUniqueID,
	netID route.NetID,
	rt []*route.Route,
	out route.HAMap,
) {
	if rs.hasUserSelectionForRouteLocked(netID) {
		if rs.isSelectedLocked(netID) {
			out[id] = rt
		}
		return
	}

	// no explicit selection for this route: defer to management's SkipAutoApply flag
	sel := collectSelected(rt)
	if len(sel) > 0 {
		out[id] = sel
	}
}

func isExitNode(rt []*route.Route) bool {
	return len(rt) > 0 && (route.IsV4DefaultRoute(rt[0].Network) || route.IsV6DefaultRoute(rt[0].Network))
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
