package routemanager

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

// send 5 routes, one for server and 4 for clients, one normal and 2 HA and one small
// if linux host, should have one for server in map
// we should have 2 client manager
// 2 ranges in our routing table

const localPeerKey = "local"
const remotePeerKey1 = "remote1"
const remotePeerKey2 = "remote1"

func TestManagerUpdateRoutes(t *testing.T) {
	testCases := []struct {
		name                          string
		inputInitRoutes               []*route.Route
		inputRoutes                   []*route.Route
		inputSerial                   uint64
		shouldCheckServerRoutes       bool
		serverRoutesExpected          int
		clientNetworkWatchersExpected int
	}{
		{
			name:            "Should create 2 client networks",
			inputInitRoutes: []*route.Route{},
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.8.8/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			clientNetworkWatchersExpected: 2,
		},
		{
			name: "Should Create 2 Server Routes",
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("100.64.252.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("8.8.8.9/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			shouldCheckServerRoutes:       runtime.GOOS == "linux",
			serverRoutesExpected:          2,
			clientNetworkWatchersExpected: 0,
		},
		{
			name: "Should Create 1 Route For Client And Server",
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("100.64.30.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.9.9/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			shouldCheckServerRoutes:       runtime.GOOS == "linux",
			serverRoutesExpected:          1,
			clientNetworkWatchersExpected: 1,
		},
		{
			name: "Should Create 1 HA Route and 1 Standalone",
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.20.0/24"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeA",
					Peer:        remotePeerKey2,
					Network:     netip.MustParsePrefix("8.8.20.0/24"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "c",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.9.9/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			clientNetworkWatchersExpected: 2,
		},
		{
			name: "No Small Client Route Should Be Added",
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("0.0.0.0/0"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			clientNetworkWatchersExpected: 0,
		},
		{
			name: "No Server Routes Should Be Added To Non Linux",
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("1.2.3.4/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			shouldCheckServerRoutes:       runtime.GOOS != "linux",
			serverRoutesExpected:          0,
			clientNetworkWatchersExpected: 0,
		},
		{
			name: "Remove 1 Client Route",
			inputInitRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.8.8/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			clientNetworkWatchersExpected: 1,
		},
		{
			name: "Update Route to HA",
			inputInitRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.8.8/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeA",
					Peer:        remotePeerKey2,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			clientNetworkWatchersExpected: 1,
		},
		{
			name: "Remove Client Routes",
			inputInitRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.8.8/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputRoutes:                   []*route.Route{},
			inputSerial:                   1,
			clientNetworkWatchersExpected: 0,
		},
		{
			name: "Remove All Routes",
			inputInitRoutes: []*route.Route{
				{
					ID:          "a",
					NetID:       "routeA",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "b",
					NetID:       "routeB",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.8.8/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputRoutes:                   []*route.Route{},
			inputSerial:                   1,
			shouldCheckServerRoutes:       true,
			serverRoutesExpected:          0,
			clientNetworkWatchersExpected: 0,
		},
		{
			name: "HA server should not register routes from the same HA group",
			inputRoutes: []*route.Route{
				{
					ID:          "l1",
					NetID:       "routeA",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "l2",
					NetID:       "routeA",
					Peer:        localPeerKey,
					Network:     netip.MustParsePrefix("8.8.9.8/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "r1",
					NetID:       "routeA",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("100.64.251.250/30"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
				{
					ID:          "r2",
					NetID:       "routeC",
					Peer:        remotePeerKey1,
					Network:     netip.MustParsePrefix("8.8.9.9/32"),
					NetworkType: route.IPv4Network,
					Metric:      9999,
					Masquerade:  false,
					Enabled:     true,
				},
			},
			inputSerial:                   1,
			shouldCheckServerRoutes:       runtime.GOOS == "linux",
			serverRoutesExpected:          2,
			clientNetworkWatchersExpected: 1,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun43%d", n), "100.65.65.2/24", iface.DefaultMTU)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			statusRecorder := peer.NewRecorder()
			ctx := context.TODO()
			routeManager := NewManager(ctx, localPeerKey, wgInterface, statusRecorder)
			defer routeManager.Stop()

			if len(testCase.inputInitRoutes) > 0 {
				err = routeManager.UpdateRoutes(testCase.inputSerial, testCase.inputRoutes)
				require.NoError(t, err, "should update routes with init routes")
			}

			err = routeManager.UpdateRoutes(testCase.inputSerial+uint64(len(testCase.inputInitRoutes)), testCase.inputRoutes)
			require.NoError(t, err, "should update routes")

			require.Len(t, routeManager.clientNetworks, testCase.clientNetworkWatchersExpected, "client networks size should match")

			if testCase.shouldCheckServerRoutes {
				require.Len(t, routeManager.serverRoutes, testCase.serverRoutesExpected, "server networks size should match")
			}
		})
	}
}
