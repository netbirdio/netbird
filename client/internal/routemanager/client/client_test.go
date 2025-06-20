package client

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
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
					status:  peer.StatusConnected,
					relayed: false,
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
					status:  peer.StatusConnected,
					relayed: true,
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
					status:  peer.StatusConnected,
					relayed: true,
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
					status:  peer.StatusConnecting,
					relayed: false,
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
					status:  peer.StatusConnected,
					relayed: false,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
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
					status:  peer.StatusConnected,
					relayed: false,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: true,
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
					status:  peer.StatusConnected,
					latency: 300 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					latency: 10 * time.Millisecond,
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
					status:  peer.StatusConnected,
					latency: 0 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					latency: 10 * time.Millisecond,
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
					status:  peer.StatusConnected,
					relayed: false,
					latency: 15 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 10 * time.Millisecond,
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
			name: "relayed routes with latency 0 should maintain previous choice",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					relayed: true,
					latency: 0 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: true,
					latency: 0 * time.Millisecond,
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
			name: "p2p routes with latency 0 should maintain previous choice",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 0 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 0 * time.Millisecond,
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
					status:  peer.StatusConnected,
					relayed: false,
					latency: 200 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 10 * time.Millisecond,
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
					status:  peer.StatusConnected,
					relayed: false,
					latency: 20 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 10 * time.Millisecond,
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
		{
			name: "connected peer should be preferred over idle peer",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 100 * time.Millisecond,
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
			name: "idle peer should be selected when no connected peers",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnecting,
					relayed: false,
					latency: 5 * time.Millisecond,
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
			name: "best idle peer should be selected among multiple idle peers",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 100 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
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
			name: "connecting peers should not be considered for routing",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnecting,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnecting,
					relayed: false,
					latency: 5 * time.Millisecond,
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
			expectedRouteID: "",
		},
		{
			name: "mixed statuses - connected wins over idle and connecting",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnecting,
					relayed: false,
					latency: 5 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route3": {
					status:  peer.StatusConnected,
					relayed: true,
					latency: 200 * time.Millisecond,
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
				"route3": {
					ID:     "route3",
					Metric: route.MaxMetric,
					Peer:   "peer3",
				},
			},
			currentRoute:    "",
			expectedRouteID: "route3",
		},
		{
			name: "idle peer with better metric should win over idle peer with worse metric",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 50 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 50 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: 5000,
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
			name: "current idle route should be maintained for similar scores",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 20 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 15 * time.Millisecond,
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
			name: "idle peer with zero latency should still be considered",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 0 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnecting,
					relayed: false,
					latency: 10 * time.Millisecond,
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
			name: "direct idle peer preferred over relayed idle peer",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: true,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 50 * time.Millisecond,
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
			name: "connected peer with worse metric still beats idle peer with better metric",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 50 * time.Millisecond,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: 1000,
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
			name: "connected peer wins even when idle peer has all advantages",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 1 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: true,
					latency: 30 * time.Minute,
				},
			},
			existingRoutes: map[route.ID]*route.Route{
				"route1": {
					ID:     "route1",
					Metric: 1,
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
			name: "connected peer should be preferred over idle peer",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
					latency: 100 * time.Millisecond,
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
			name: "idle peer should be selected when no connected peers",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnecting,
					relayed: false,
					latency: 5 * time.Millisecond,
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
			name: "best idle peer should be selected among multiple idle peers",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 100 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusIdle,
					relayed: false,
					latency: 10 * time.Millisecond,
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
	}

	// fill the test data with random routes
	for _, tc := range testCases {
		for i := 0; i < 50; i++ {
			dummyRoute := &route.Route{
				ID:     route.ID(fmt.Sprintf("dummy_p1_%d", i)),
				Metric: route.MinMetric,
				Peer:   fmt.Sprintf("dummy_p1_%d", i),
			}
			tc.existingRoutes[dummyRoute.ID] = dummyRoute
		}
		for i := 0; i < 50; i++ {
			dummyRoute := &route.Route{
				ID:     route.ID(fmt.Sprintf("dummy_p2_%d", i)),
				Metric: route.MinMetric,
				Peer:   fmt.Sprintf("dummy_p1_%d", i),
			}
			tc.existingRoutes[dummyRoute.ID] = dummyRoute
		}

		for i := 0; i < 50; i++ {
			id := route.ID(fmt.Sprintf("dummy_p1_%d", i))
			dummyStatus := routerPeerStatus{
				status:  peer.StatusConnecting,
				relayed: true,
				latency: 0,
			}
			tc.statuses[id] = dummyStatus
		}
		for i := 0; i < 50; i++ {
			id := route.ID(fmt.Sprintf("dummy_p2_%d", i))
			dummyStatus := routerPeerStatus{
				status:  peer.StatusConnecting,
				relayed: true,
				latency: 0,
			}
			tc.statuses[id] = dummyStatus
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentRoute := &route.Route{
				ID: "routeDoesntExistAnymore",
			}
			if tc.currentRoute != "" {
				currentRoute = tc.existingRoutes[tc.currentRoute]
			}

			params := common.HandlerParams{
				Route:               &route.Route{Network: netip.MustParsePrefix("192.168.0.0/24")},
			}
			// create new clientNetwork
			client := &Watcher{
				handler:       static.NewRoute(params),
				routes:        tc.existingRoutes,
				currentChosen: currentRoute,
			}

			chosenRoute, _ := client.getBestRouteFromStatuses(tc.statuses)
			if chosenRoute != tc.expectedRouteID {
				t.Errorf("expected routeID %s, got %s", tc.expectedRouteID, chosenRoute)
			}
		})
	}
}
