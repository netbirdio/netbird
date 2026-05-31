package routeselector

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

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

// IsSelected checks if a specific route is selected.
func (rs *RouteSelector) IsSelected(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return rs.isSelectedLocked(routeID)
}

// IsSelectedForExitNode checks if an exit-node route is selected, mirroring the
// v4/v6 pair: a synthesized "-v6" entry with no explicit state of its own inherits
// its v4 base's selection, so a deselect on the v4 base also deselects the v6 entry.
// Only call this from exit-node code paths (see effectiveNetID).
func (rs *RouteSelector) IsSelectedForExitNode(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return rs.isSelectedLocked(rs.effectiveNetID(routeID))
}

// MarshalSummary returns a short human-readable description of the selector state for diagnostics.
func (rs *RouteSelector) MarshalSummary() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return fmt.Sprintf("deselectAll=%v selected=%v deselected=%v", rs.deselectAll, keysOf(rs.selectedRoutes), keysOf(rs.deselectedRoutes))
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
// Intended for exit-node code paths: a v6 exit-node pair (e.g. "MyExit-v6") with no explicit state of
// its own inherits its v4 base's state, so legacy persisted selections that predate v6 pairing
// transparently apply to the synthesized v6 entry.
func (rs *RouteSelector) HasUserSelectionForRoute(routeID route.NetID) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return rs.hasUserSelectionForRouteLocked(rs.effectiveNetID(routeID))
}

func (rs *RouteSelector) FilterSelectedExitNodes(routes route.HAMap) route.HAMap {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.deselectAll {
		return route.HAMap{}
	}

	log.Debugf("DIAG FilterSelectedExitNodes: incoming %d networks, deselected=%v selected=%v deselectAll=%v",
		len(routes), keysOf(rs.deselectedRoutes), keysOf(rs.selectedRoutes), rs.deselectAll)

	filtered := make(route.HAMap, len(routes))
	for id, rt := range routes {
		netID := id.NetID()
		if rs.isDeselectedLocked(netID) {
			log.Debugf("DIAG FilterSelectedExitNodes: SKIP id=%q netID=%q (literally deselected)", id, netID)
			continue
		}

		if !isExitNode(rt) {
			log.Debugf("DIAG FilterSelectedExitNodes: KEEP id=%q netID=%q (not an exit node)", id, netID)
			filtered[id] = rt
			continue
		}

		log.Debugf("DIAG FilterSelectedExitNodes: EXITNODE id=%q netID=%q -> applyExitNodeFilter", id, netID)
		rs.applyExitNodeFilter(id, netID, rt, filtered)
	}

	log.Debugf("DIAG FilterSelectedExitNodes: result keeps %d networks: %v", len(filtered), haKeysOf(filtered))
	return filtered
}

func keysOf(m map[route.NetID]struct{}) []route.NetID {
	out := make([]route.NetID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func haKeysOf(m route.HAMap) []route.HAUniqueID {
	out := make([]route.HAUniqueID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// effectiveNetID returns the v4 base for a "-v6" exit pair entry that has no explicit
// state of its own, so selections made on the v4 entry govern the v6 entry automatically.
// Only call this from exit-node-specific code paths: applying it to a non-exit "-v6" route
// would make it inherit unrelated v4 state. Must be called with rs.mu held.
func (rs *RouteSelector) effectiveNetID(id route.NetID) route.NetID {
	name := string(id)
	if !strings.HasSuffix(name, route.V6ExitSuffix) {
		return id
	}
	if _, ok := rs.selectedRoutes[id]; ok {
		return id
	}
	if _, ok := rs.deselectedRoutes[id]; ok {
		return id
	}
	return route.NetID(strings.TrimSuffix(name, route.V6ExitSuffix))
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

func isExitNode(rt []*route.Route) bool {
	return len(rt) > 0 && (route.IsV4DefaultRoute(rt[0].Network) || route.IsV6DefaultRoute(rt[0].Network))
}

func (rs *RouteSelector) applyExitNodeFilter(
	id route.HAUniqueID,
	netID route.NetID,
	rt []*route.Route,
	out route.HAMap,
) {
	// Exit-node path: apply the v4/v6 pair mirror so a deselect on the v4 base also
	// drops the synthesized v6 entry that lacks its own explicit state.
	effective := rs.effectiveNetID(netID)
	log.Debugf("DIAG applyExitNodeFilter: id=%q netID=%q effective=%q hasUserSel=%v isSelected=%v",
		id, netID, effective, rs.hasUserSelectionForRouteLocked(effective), rs.isSelectedLocked(effective))
	if rs.hasUserSelectionForRouteLocked(effective) {
		if rs.isSelectedLocked(effective) {
			log.Debugf("DIAG applyExitNodeFilter: KEEP id=%q (effective %q is selected)", id, effective)
			out[id] = rt
		} else {
			log.Debugf("DIAG applyExitNodeFilter: DROP id=%q (effective %q is deselected)", id, effective)
		}
		return
	}

	// no explicit selection for this route: defer to management's SkipAutoApply flag
	sel := collectSelected(rt)
	log.Debugf("DIAG applyExitNodeFilter: no user selection for effective %q; SkipAutoApply filter kept %d/%d routes for id=%q",
		effective, len(sel), len(rt), id)
	if len(sel) > 0 {
		out[id] = sel
	}
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
