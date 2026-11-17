package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
)

func exitNodeRoutes(netID route.NetID, skipAutoApply bool) route.HAMap {
	haID := route.HAUniqueID(string(netID) + "|0.0.0.0/0")
	return route.HAMap{
		haID: []*route.Route{
			{
				ID:            "r-" + route.ID(netID),
				NetID:         netID,
				Network:       netip.MustParsePrefix("0.0.0.0/0"),
				NetworkType:   route.IPv4Network,
				Enabled:       true,
				SkipAutoApply: skipAutoApply,
			},
		},
	}
}

func TestUpdateRouteSelectorFromManagement(t *testing.T) {
	t.Run("management auto-apply selects exit node without user selection", func(t *testing.T) {
		m := &DefaultManager{routeSelector: routeselector.NewRouteSelector()}
		routes := exitNodeRoutes("exit1", false)

		m.updateRouteSelectorFromManagement(routes)

		require.True(t, m.routeSelector.IsSelected("exit1"), "auto-apply exit node should be selected")
		require.Len(t, m.routeSelector.FilterSelectedExitNodes(routes), 1, "selected exit node should pass the filter")
	})

	t.Run("management SkipAutoApply leaves exit node deselected", func(t *testing.T) {
		m := &DefaultManager{routeSelector: routeselector.NewRouteSelector()}
		routes := exitNodeRoutes("exit1", true)

		m.updateRouteSelectorFromManagement(routes)

		require.False(t, m.routeSelector.IsSelected("exit1"), "SkipAutoApply exit node should not be selected")
		require.Empty(t, m.routeSelector.FilterSelectedExitNodes(routes), "deselected exit node should be filtered out")
	})

	t.Run("user selection is not overridden by management", func(t *testing.T) {
		m := &DefaultManager{routeSelector: routeselector.NewRouteSelector()}
		require.NoError(t, m.routeSelector.SelectRoutes([]route.NetID{"exit1"}, true, []route.NetID{"exit1"}))
		routes := exitNodeRoutes("exit1", true)

		m.updateRouteSelectorFromManagement(routes)

		require.True(t, m.routeSelector.IsSelected("exit1"), "explicit user selection must survive a management sync that wants to skip auto-apply")
		require.Len(t, m.routeSelector.FilterSelectedExitNodes(routes), 1, "user-selected exit node should pass the filter")
	})

	t.Run("deselect-all is preserved across a management sync", func(t *testing.T) {
		m := &DefaultManager{routeSelector: routeselector.NewRouteSelector()}
		m.routeSelector.DeselectAllRoutes()
		routes := exitNodeRoutes("exit1", false)

		m.updateRouteSelectorFromManagement(routes)

		require.True(t, m.routeSelector.IsDeselectAll(), "an explicit deselect-all must not be cleared by management auto-apply")
		require.Empty(t, m.routeSelector.FilterSelectedExitNodes(routes), "no routes should be selected while deselect-all is set")
	})
}
