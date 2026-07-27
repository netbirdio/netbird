package routemanager

import (
	"fmt"
	"slices"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/route"
)

// SelectRoutes selects the routes with the given network IDs and applies the
// new selection. V4/v6 exit-node pairs are expanded automatically. Exit nodes
// are mutually exclusive: if the selection activates an exit node, every other
// available exit node is deselected so two can't be active at once. With
// appendRoute=false the previous selection is replaced instead of extended.
func (m *DefaultManager) SelectRoutes(ids []route.NetID, appendRoute bool) error {
	if err := m.selectRoutes(ids, appendRoute); err != nil {
		return err
	}
	m.TriggerSelection(m.GetClientRoutes())
	return nil
}

// DeselectRoutes removes the routes with the given network IDs from the
// selection and applies the change. V4/v6 exit-node pairs are expanded
// automatically.
func (m *DefaultManager) DeselectRoutes(ids []route.NetID) error {
	if err := m.deselectRoutes(ids); err != nil {
		return err
	}
	m.TriggerSelection(m.GetClientRoutes())
	return nil
}

func (m *DefaultManager) deselectRoutes(ids []route.NetID) error {
	routesMap := m.GetClientRoutesWithNetID()
	routes := route.ExpandV6ExitPairs(slices.Clone(ids), routesMap)

	log.Debugf("deselecting routes with ids: %v", routes)

	if err := m.routeSelector.DeselectRoutes(routes, maps.Keys(routesMap)); err != nil {
		return fmt.Errorf("deselect routes: %w", err)
	}

	return nil
}

// SelectAllRoutes selects every available route and applies the selection.
func (m *DefaultManager) SelectAllRoutes() {
	m.routeSelector.SelectAllRoutes()
	m.TriggerSelection(m.GetClientRoutes())
}

// DeselectAllRoutes deselects every route and applies the change.
func (m *DefaultManager) DeselectAllRoutes() {
	m.routeSelector.DeselectAllRoutes()
	m.TriggerSelection(m.GetClientRoutes())
}

func (m *DefaultManager) selectRoutes(ids []route.NetID, appendRoute bool) error {
	routesMap := m.GetClientRoutesWithNetID()
	routes := route.ExpandV6ExitPairs(slices.Clone(ids), routesMap)
	allIDs := maps.Keys(routesMap)

	log.Debugf("selecting routes with ids: %v", routes)

	if err := m.routeSelector.SelectRoutes(routes, appendRoute, allIDs); err != nil {
		return fmt.Errorf("select routes: %w", err)
	}

	// Exit nodes are mutually exclusive: if this selection activates an
	// exit node, deselect every other available exit node so two can't be
	// selected at once. Non-exit route selections are left untouched.
	if requestActivatesExitNode(routes, routesMap) {
		if others := otherExitNodeIDs(routesMap, routes); len(others) > 0 {
			if err := m.routeSelector.DeselectRoutes(others, allIDs); err != nil {
				return fmt.Errorf("deselect sibling exit nodes: %w", err)
			}
		}
	}

	return nil
}

func isExitNodeRoutes(routes []*route.Route) bool {
	return len(routes) > 0 && (route.IsV4DefaultRoute(routes[0].Network) || route.IsV6DefaultRoute(routes[0].Network))
}

// requestActivatesExitNode reports whether any requested NetID maps to an exit
// node (default route) in the current route table.
func requestActivatesExitNode(requested []route.NetID, routesMap map[route.NetID][]*route.Route) bool {
	for _, id := range requested {
		if isExitNodeRoutes(routesMap[id]) {
			return true
		}
	}
	return false
}

// otherExitNodeIDs returns every available exit-node NetID that is not in the
// requested set — the siblings to deselect so a single exit node stays active.
func otherExitNodeIDs(routesMap map[route.NetID][]*route.Route, requested []route.NetID) []route.NetID {
	keep := make(map[route.NetID]struct{}, len(requested))
	for _, id := range requested {
		keep[id] = struct{}{}
	}
	var others []route.NetID
	for id, routes := range routesMap {
		if !isExitNodeRoutes(routes) {
			continue
		}
		if _, ok := keep[id]; ok {
			continue
		}
		others = append(others, id)
	}
	return others
}
