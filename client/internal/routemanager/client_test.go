package routemanager

import (
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/routemanager/static"
	"github.com/netbirdio/netbird/route"
)

func TestGetBestrouteFromStatuses(t *testing.T) {

	testCases := []struct {
		name            string
		statuses        map[route.ID]routerPeerStatus
		expectedRouteID route.ID
		currentRoute    route.ID
		existingRoutes  map[route.ID]*route.Route
	}{
		{
			name: "one route",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    "",
			expectedRouteID: "route1",
		},
		{
			name: "one connected routes with relayed and direct",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   true,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    "",
			expectedRouteID: "route1",
		},
		{
			name: "one connected routes with relayed and no direct",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   true,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    "",
			expectedRouteID: "route1",
		},
		{
			name: "no connected peers",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: false,
					relayed:   false,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: route.MaxMetric,
					Peer:   "peer1",
				},
			},
			currentRoute:    "",
			expectedRouteID: "",
		},
		{
			name: "multiple connected peers with different metrics",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
				},
				"route2": {
					connected: true,
					relayed:   false,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "",
			expectedRouteID: "route1",
		},
		{
			name: "multiple connected peers with one relayed",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
				},
				"route2": {
					connected: true,
					relayed:   true,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "",
			expectedRouteID: "route1",
		},
		{
			name: "multiple connected peers with different latencies",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					latency:   300 * time.Millisecond,
				},
				"route2": {
					connected: true,
					latency:   10 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "",
			expectedRouteID: "route2",
		},
		{
			name: "should ignore routes with latency 0",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					latency:   0 * time.Millisecond,
				},
				"route2": {
					connected: true,
					latency:   10 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "",
			expectedRouteID: "route2",
		},
		{
			name: "current route with similar score and similar but slightly worse latency should not change",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					latency:   15 * time.Millisecond,
				},
				"route2": {
					connected: true,
					relayed:   false,
					latency:   10 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "route1",
			expectedRouteID: "route1",
		},
		{
			name: "current route with bad score should be changed to route with better score",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					latency:   200 * time.Millisecond,
				},
				"route2": {
					connected: true,
					relayed:   false,
					latency:   10 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "route1",
			expectedRouteID: "route2",
		},
		{
			name: "current chosen route doesn't exist anymore",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					connected: true,
					relayed:   false,
					latency:   20 * time.Millisecond,
				},
				"route2": {
					connected: true,
					relayed:   false,
					latency:   10 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
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
			currentRoute:    "routeDoesntExistAnymore",
			expectedRouteID: "route2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentRoute := &route.Route{
				ID: "routeDoesntExistAnymore",
			}
			if tc.currentRoute != "" {
				currentRoute = tc.existingRoutes[tc.currentRoute]
			}

			// create new clientNetwork
			client := &clientNetwork{
				handler:       static.NewRoute(&route.Route{Network: netip.MustParsePrefix("192.168.0.0/24")}, nil, nil),
				routes:        tc.existingRoutes,
				currentChosen: currentRoute,
			}

			chosenRoute := client.getBestRouteFromStatuses(tc.statuses)
			if chosenRoute != tc.expectedRouteID {
				t.Errorf("expected routeID %s, got %s", tc.expectedRouteID, chosenRoute)
			}
		})
	}
}
