package client

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			// 40ms gain clears latencySwitchMinGain but not the 20% of 300ms
			name: "latency gain below the relative margin should not change the route",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					latency: 300 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					latency: 260 * time.Millisecond,
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
			name: "latency gain above both margins should change the route",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					latency: 300 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
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
			},
			currentRoute:    "route1",
			expectedRouteID: "route2",
		},
		{
			// 7ms gain is 58% of the current latency but below latencySwitchMinGain
			name: "latency gain below the absolute margin should not change the route",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					latency: 12 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
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
			currentRoute:    "route1",
			expectedRouteID: "route1",
		},
		{
			name: "current relayed peer should be replaced by a direct peer with worse latency",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					relayed: true,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					relayed: false,
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
			},
			currentRoute:    "route1",
			expectedRouteID: "route2",
		},
		{
			name: "better metric should replace the current peer with better latency",
			statuses: map[route.ID]routerPeerStatus{
				"route1": {
					status:  peer.StatusConnected,
					latency: 10 * time.Millisecond,
				},
				"route2": {
					status:  peer.StatusConnected,
					latency: 300 * time.Millisecond,
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
					Metric: 5000,
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
				Route: &route.Route{Network: netip.MustParsePrefix("192.168.0.0/24")},
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

// newTestWatcher builds a watcher over two routes of equal metric, with route1
// as the currently chosen one.
func newTestWatcher(t *testing.T, lastSwitch time.Time) *Watcher {
	t.Helper()

	routes := map[route.ID]*route.Route{
		"route1": {ID: "route1", Metric: route.MaxMetric, Peer: "peer1"},
		"route2": {ID: "route2", Metric: route.MaxMetric, Peer: "peer2"},
	}

	params := common.HandlerParams{
		Route: &route.Route{Network: netip.MustParsePrefix("192.168.0.0/24")},
	}

	return &Watcher{
		handler:       static.NewRoute(params),
		routes:        routes,
		currentChosen: routes["route1"],
		lastSwitch:    lastSwitch,
	}
}

func TestLatencySwitchDwellTime(t *testing.T) {
	// a gain large enough to clear both switch margins
	statuses := map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 300 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 100 * time.Millisecond},
	}

	t.Run("latency switch is held during the dwell time", func(t *testing.T) {
		w := newTestWatcher(t, time.Now())

		chosen, _ := w.getBestRouteFromStatuses(statuses)
		assert.Equal(t, route.ID("route1"), chosen, "route should be kept while the dwell time has not elapsed")
	})

	t.Run("latency switch is allowed after the dwell time", func(t *testing.T) {
		w := newTestWatcher(t, time.Now().Add(-latencySwitchMinDwell-time.Second))

		chosen, _ := w.getBestRouteFromStatuses(statuses)
		assert.Equal(t, route.ID("route2"), chosen, "route should switch once the dwell time has elapsed")
	})

	t.Run("categorical improvement ignores the dwell time", func(t *testing.T) {
		w := newTestWatcher(t, time.Now())

		// route1 is no longer connected, so the dwell time must not delay failover
		chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusIdle, latency: 10 * time.Millisecond},
			"route2": {status: peer.StatusConnected, latency: 300 * time.Millisecond},
		})
		assert.Equal(t, route.ID("route2"), chosen, "failover must not be delayed by the dwell time")
	})
}

// TestLatencySwitchNoiseMargin covers the noise aware margin: on a jittery path
// the smoothed latencies of two equivalent peers keep drifting apart by tens of
// milliseconds, and that difference must not move the route even though it
// clears the fixed margins.
func TestLatencySwitchNoiseMargin(t *testing.T) {
	t.Run("a gain within the measurement noise does not switch", func(t *testing.T) {
		w := newTestWatcher(t, time.Time{})

		chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, latency: 120 * time.Millisecond, noise: 12 * time.Millisecond},
			"route2": {status: peer.StatusConnected, latency: 80 * time.Millisecond, noise: 12 * time.Millisecond},
		})
		assert.Equal(t, route.ID("route1"), chosen, "a 40ms gain between two paths jittering by 12ms is not a real difference")
	})

	t.Run("a gain beyond the measurement noise switches", func(t *testing.T) {
		w := newTestWatcher(t, time.Time{})

		chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, latency: 300 * time.Millisecond, noise: 12 * time.Millisecond},
			"route2": {status: peer.StatusConnected, latency: 80 * time.Millisecond, noise: 12 * time.Millisecond},
		})
		assert.Equal(t, route.ID("route2"), chosen, "a 220ms gain stands out from 12ms of jitter")
	})

	// the held candidate is tracked so the decision is reported once per episode
	// rather than on every re-evaluation
	t.Run("holding a candidate back is tracked as one episode", func(t *testing.T) {
		w := newTestWatcher(t, time.Time{})

		within := map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, latency: 120 * time.Millisecond, noise: 12 * time.Millisecond},
			"route2": {status: peer.StatusConnected, latency: 80 * time.Millisecond, noise: 12 * time.Millisecond},
		}

		w.getBestRouteFromStatuses(within)
		assert.Equal(t, route.ID("route2"), w.heldCandidate, "the held candidate should be recorded on the first hold")

		w.getBestRouteFromStatuses(within)
		assert.Equal(t, route.ID("route2"), w.heldCandidate, "a repeated hold of the same candidate stays the same episode")

		// the smoothed latencies of two near-equal peers keep crossing: route2
		// falling behind for a moment must not start a new episode
		w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, latency: 80 * time.Millisecond, noise: 12 * time.Millisecond},
			"route2": {status: peer.StatusConnected, latency: 120 * time.Millisecond, noise: 12 * time.Millisecond},
		})
		held := routeCandidate{id: "route2"}
		assert.Equal(t, log.DebugLevel, w.holdLevel(held, holdLatencyMargin), "holding route2 back again after a crossing is a repeat")

		// a hold reported long ago is worth reporting again
		w.heldReported = w.heldReported.Add(-holdReportInterval - time.Second)
		assert.Equal(t, log.InfoLevel, w.holdLevel(held, holdLatencyMargin), "a hold is reported again once the report interval passed")
	})

	t.Run("a stable path is decided by the fixed margins", func(t *testing.T) {
		w := newTestWatcher(t, time.Time{})

		// the same 40ms gain as the first case, on paths that barely vary
		chosen, _ := w.getBestRouteFromStatuses(map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, latency: 120 * time.Millisecond, noise: 300 * time.Microsecond},
			"route2": {status: peer.StatusConnected, latency: 80 * time.Millisecond, noise: 300 * time.Microsecond},
		})
		assert.Equal(t, route.ID("route2"), chosen, "without jitter a 40ms gain on a 120ms path is a real improvement")
	})
}

// recordingHandler records the allowed IPs calls a watcher makes.
type recordingHandler struct {
	added   []string
	removed int
}

func (h *recordingHandler) String() string                 { return "recording" }
func (h *recordingHandler) AddRoute(context.Context) error { return nil }
func (h *recordingHandler) RemoveRoute() error             { return nil }
func (h *recordingHandler) AddAllowedIPs(peerKey string) error {
	h.added = append(h.added, peerKey)
	return nil
}

func (h *recordingHandler) RemoveAllowedIPs() error {
	h.removed++
	return nil
}

func newRecalcWatcher(t *testing.T) (*Watcher, *recordingHandler) {
	t.Helper()

	handler := &recordingHandler{}
	routes := map[route.ID]*route.Route{
		"route1": {ID: "route1", Metric: route.MaxMetric, Peer: "peer1"},
		"route2": {ID: "route2", Metric: route.MaxMetric, Peer: "peer2"},
	}

	return &Watcher{
		statusRecorder: peer.NewRecorder("https://mgm"),
		routes:         routes,
		handler:        handler,
	}, handler
}

// TestRecalculateRoutesAssignsIdlePeer covers the lazy connection path: an idle
// routing peer has no established connection yet, but must still receive the
// allowed IPs so that traffic for the route can trigger the connection.
func TestRecalculateRoutesAssignsIdlePeer(t *testing.T) {
	w, handler := newRecalcWatcher(t)

	err := w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusIdle},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"peer1"}, handler.added, "an idle routing peer should still get the allowed IPs")
	require.NotNil(t, w.currentChosen, "an idle peer should be chosen when it is the only candidate")
	assert.Equal(t, route.ID("route1"), w.currentChosen.ID)
}

func TestRecalculateRoutesDwellTime(t *testing.T) {
	w, handler := newRecalcWatcher(t)

	// route2 has no status yet, so route1 is the only candidate
	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 300 * time.Millisecond},
	}))
	require.Equal(t, []string{"peer1"}, handler.added)
	require.True(t, w.lastSwitch.IsZero(), "the initial assignment is not latency-driven and must not arm the dwell time")

	betterRoute2 := map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 300 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 100 * time.Millisecond},
	}

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, betterRoute2))
	assert.Equal(t, []string{"peer1", "peer2"}, handler.added, "a latency switch with no recent switch should be allowed")
	assert.Equal(t, 1, handler.removed)
	require.False(t, w.lastSwitch.IsZero(), "a latency-driven switch must arm the dwell time")

	// the peers trade places: switching back is again latency-only, but now
	// inside the dwell window
	betterRoute1 := map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 100 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 300 * time.Millisecond},
	}

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, betterRoute1))
	assert.Equal(t, []string{"peer1", "peer2"}, handler.added, "the route should be held during the dwell time")

	w.lastSwitch = w.lastSwitch.Add(-latencySwitchMinDwell - time.Second)

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, betterRoute1))
	assert.Equal(t, []string{"peer1", "peer2", "peer1"}, handler.added, "the route should switch once the dwell time elapsed")
	assert.Equal(t, 2, handler.removed)

	// the switch re-armed the dwell time, which must not delay failover
	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnecting, latency: 100 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 300 * time.Millisecond},
	}))
	assert.Equal(t, []string{"peer1", "peer2", "peer1", "peer2"}, handler.added, "losing the routing peer must fail over regardless of the dwell time")
	assert.Equal(t, 3, handler.removed)
}

// TestFailoverDoesNotArmDwellTime covers the recovery path: a failover to a
// worse peer must not start the dwell time, or traffic would be stuck on the
// worse path for the full dwell after the better peer comes back.
func TestFailoverDoesNotArmDwellTime(t *testing.T) {
	w, handler := newRecalcWatcher(t)

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 20 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 200 * time.Millisecond},
	}))
	require.Equal(t, []string{"peer1"}, handler.added)

	// peer1 blips into connecting: unguarded failover to the worse peer2
	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnecting, latency: 20 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 200 * time.Millisecond},
	}))
	require.Equal(t, []string{"peer1", "peer2"}, handler.added, "failover to the remaining peer should happen")
	require.True(t, w.lastSwitch.IsZero(), "a failover must not arm the dwell time")

	// peer1 recovers seconds later: the return is latency-only but must not be
	// held back by a dwell the failover would have armed
	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 20 * time.Millisecond},
		"route2": {status: peer.StatusConnected, latency: 200 * time.Millisecond},
	}))
	assert.Equal(t, []string{"peer1", "peer2", "peer1"}, handler.added, "the recovered better peer should take the route back immediately")
}

// TestStopWaitsForStart covers the shutdown ordering: Stop must not clean up
// while the Start loop may still be inside a recalculation triggered by the
// periodic re-evaluation.
func TestStopWaitsForStart(t *testing.T) {
	handler := &recordingHandler{}
	w := NewWatcher(WatcherConfig{
		Context:        context.Background(),
		StatusRecorder: peer.NewRecorder("https://mgm"),
		Handler:        handler,
	})

	started := make(chan struct{})
	go func() {
		close(started)
		w.Start()
	}()
	<-started

	finished := make(chan struct{})
	go func() {
		w.Stop()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop should return once the Start loop has exited")
	}
}

// TestStopWithoutStart covers a watcher whose Start goroutine never ran, or ran
// only after Stop: Stop must return instead of waiting for a loop that does not
// exist, and a late Start must not begin working on a stopped watcher.
// A peer state notification can reach the watcher after a newer one: each
// routing peer has its own subscription and forwarder, and all of them feed the
// same channel. The watcher must act on the recorded peer states rather than on
// the states the notification carried, or it could move the route back onto a
// routing peer that has since gone away.
func TestOutdatedPeerStateNotificationIsNotApplied(t *testing.T) {
	w, handler := newRecalcWatcher(t)

	recorder := w.statusRecorder
	for _, key := range []string{"peer1", "peer2"} {
		require.NoError(t, recorder.AddPeer(key, key+".netbird.cloud", "100.64.0.1", ""))
	}
	require.NoError(t, recorder.UpdatePeerState(peer.State{PubKey: "peer1", ConnStatus: peer.StatusConnected}))
	require.NoError(t, recorder.UpdatePeerState(peer.State{PubKey: "peer2", ConnStatus: peer.StatusConnecting}))

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, w.getRouterPeerStatuses()))
	require.Equal(t, []string{"peer1"}, handler.added)

	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.done = make(chan struct{})
	w.peerStateUpdate = make(chan map[string]peer.RouterState)
	go w.Start()

	// built while peer2 was still up and peer1 was not, delivered late
	w.peerStateUpdate <- map[string]peer.RouterState{
		"peer1": {Status: peer.StatusConnecting},
		"peer2": {Status: peer.StatusConnected},
	}
	w.Stop()

	assert.Equal(t, []string{"peer1"}, handler.added, "an outdated notification must not move the route to a routing peer that is gone")
}

func TestStopWithoutStart(t *testing.T) {
	w := NewWatcher(WatcherConfig{
		Context:        context.Background(),
		StatusRecorder: peer.NewRecorder("https://mgm"),
		Handler:        &recordingHandler{},
	})

	finished := make(chan struct{})
	go func() {
		w.Stop()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop must return when Start was never called")
	}

	started := make(chan struct{})
	go func() {
		w.Start()
		close(started)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("Start after Stop must return immediately")
	}
}

// TestUnassignedNetworkReportedOncePerEpisode covers the no-routing-peer log:
// the periodic re-evaluation hits the same branch every tick, so the episode
// must be reported once, and again only after a route was assigned in between.
func TestUnassignedNetworkReportedOncePerEpisode(t *testing.T) {
	w, _ := newRecalcWatcher(t)

	unassigned := map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnecting},
	}
	assigned := map[route.ID]routerPeerStatus{
		"route1": {status: peer.StatusConnected, latency: 10 * time.Millisecond},
	}

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, unassigned))
	assert.True(t, w.reportedUnassigned, "the first unassigned evaluation should be reported")

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, unassigned))
	assert.True(t, w.reportedUnassigned, "repeats stay within the same episode")

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, assigned))
	assert.False(t, w.reportedUnassigned, "an assigned route ends the episode")

	require.NoError(t, w.recalculateRoutes(reasonPeerUpdate, unassigned))
	assert.True(t, w.reportedUnassigned, "losing the route again starts a new episode")
}

// TestLatencyJitterDoesNotSwitchRoute walks two equivalent peers through jitter
// around the same mean. Neither peer is genuinely better, so the route must not
// move at any point.
func TestLatencyJitterDoesNotSwitchRoute(t *testing.T) {
	w := newTestWatcher(t, time.Time{})

	jitter := []int{-6, 3, -4, 8, -2, 5, -7, 1, 6, -3}
	for i, offsetMs := range jitter {
		offset := time.Duration(offsetMs) * time.Millisecond
		statuses := map[route.ID]routerPeerStatus{
			"route1": {status: peer.StatusConnected, latency: 20*time.Millisecond + offset},
			"route2": {status: peer.StatusConnected, latency: 20*time.Millisecond - offset},
		}

		chosen, _ := w.getBestRouteFromStatuses(statuses)
		require.Equal(t, route.ID("route1"), chosen, "route changed on jitter at sample %d", i)
	}
}
