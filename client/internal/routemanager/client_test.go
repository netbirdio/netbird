package routemanager

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/route"
)

func TestGetBestrouteFromStatuses(t *testing.T) {

	testCases := []struct {
		name            string
		statuses        map[string]routerPeerStatus
		expectedRouteID string
		currentRoute    *route.Route
		existingRoutes  map[string]*route.Route
	}{
		{
			name: "one route",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "route1",
		},
		{
			name: "one connected routes with relayed and direct",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   true,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "route1",
		},
		{
			name: "one connected routes with relayed and no direct",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   true,
					direct:    false,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "route1",
		},
		{
			name: "no connected peers",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: false,
					relayed:   false,
					direct:    false,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "",
		},
		{
			name: "multiple connected peers with different metrics",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
				"route2": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: 9000,
					Peer:   "peer1",
				},
				"route2": {
					ID:     "route2",
					Metric: route.MaxMetric,
					Peer:   "peer2",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "route1",
		},
		{
			name: "multiple connected peers with one relayed",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
				"route2": {
					connected: true,
					relayed:   true,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
				"route2": {
					ID:     "route2",
					Metric: route.MaxMetric,
					Peer:   "peer2",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "route1",
		},
		{
			name: "multiple connected peers with one direct",
			statuses: map[string]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
				"route2": {
					connected: true,
					relayed:   false,
					direct:    false,
				},
			},
			existingRoutes: map[string]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
				"route2": {
					ID:     "route2",
					Metric: route.MaxMetric,
					Peer:   "peer2",
				},
			},
			currentRoute:    nil,
			expectedRouteID: "route1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// create new clientNetwork
			client := &clientNetwork{
				network:     netip.MustParsePrefix("192.168.0.0/24"),
				routes:      tc.existingRoutes,
				chosenRoute: tc.currentRoute,
			}

			chosenRoute := client.getBestRouteFromStatuses(tc.statuses)
			if chosenRoute != tc.expectedRouteID {
				t.Errorf("expected routeID %s, got %s", tc.expectedRouteID, chosenRoute)
			}
		})
	}
}
