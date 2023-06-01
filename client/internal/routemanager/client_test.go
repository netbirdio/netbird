package routemanager

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/route"
)

// unit test for getBestrouteFromStatuses
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
				"peer1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"peer1": {
					ID:     "peer1",
					Metric: route.MaxMetric,
				},
			},
			currentRoute:    nil,
			expectedRouteID: "peer1",
		},
		{
			name: "one connected routes with relayed and direct",
			statuses: map[string]routerPeerStatus{
				"peer1": {
					connected: true,
					relayed:   true,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"peer1": {
					ID:     "peer1",
					Metric: route.MaxMetric,
				},
			},
			currentRoute:    nil,
			expectedRouteID: "peer1",
		},
		{
			name: "no connected peers",
			statuses: map[string]routerPeerStatus{
				"peer1": {
					connected: false,
					relayed:   false,
					direct:    false,
				},
			},
			existingRoutes: map[string]*route.Route{
				"peer1": {
					ID:     "peer1",
					Metric: route.MaxMetric,
				},
			},
			currentRoute:    nil,
			expectedRouteID: "",
		},
		{
			name: "multiple connected peers with different metrics",
			statuses: map[string]routerPeerStatus{
				"peer1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
				"peer2": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"peer1": {
					ID:     "peer1",
					Metric: 9000,
				},
				"peer2": {
					ID:     "peer2",
					Metric: route.MaxMetric,
				},
			},
			currentRoute:    nil,
			expectedRouteID: "peer1",
		},
		{
			name: "multiple connected peers with one relayed",
			statuses: map[string]routerPeerStatus{
				"peer1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
				"peer2": {
					connected: true,
					relayed:   true,
					direct:    true,
				},
			},
			existingRoutes: map[string]*route.Route{
				"peer1": {
					ID:     "peer1",
					Metric: route.MaxMetric,
				},
				"peer2": {
					ID:     "peer2",
					Metric: route.MaxMetric,
				},
			},
			currentRoute:    nil,
			expectedRouteID: "peer1",
		},
		{
			name: "multiple connected peers with one direct",
			statuses: map[string]routerPeerStatus{
				"peer1": {
					connected: true,
					relayed:   false,
					direct:    true,
				},
				"peer2": {
					connected: true,
					relayed:   false,
					direct:    false,
				},
			},
			existingRoutes: map[string]*route.Route{
				"peer1": {
					ID:     "peer1",
					Metric: route.MaxMetric,
				},
				"peer2": {
					ID:     "peer2",
					Metric: route.MaxMetric,
				},
			},
			currentRoute:    nil,
			expectedRouteID: "peer1",
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
