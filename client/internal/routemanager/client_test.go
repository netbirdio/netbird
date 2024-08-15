package routemanager

import (
	"net/netip"
	"testing"

	log "github.com/sirupsen/logrus"

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
			name: "multiple connected peers with one direct",
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
	}

	for i := 0; i < 10; i++ {
		log.Infof("Test iteration %d", i)
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
}
