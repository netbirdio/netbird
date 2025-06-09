package client

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

type benchmarkTier struct {
	name            string
	peers           int
	routes          int
	haPeersPerGroup int
}

var benchmarkTiers = []benchmarkTier{
	{"Small", 100, 50, 4},
	{"Medium", 1000, 200, 16},
	{"Large", 5000, 500, 32},
}

type mockRouteHandler struct {
	network string
}

func (m *mockRouteHandler) String() string                 { return m.network }
func (m *mockRouteHandler) AddRoute(context.Context) error { return nil }
func (m *mockRouteHandler) RemoveRoute() error             { return nil }
func (m *mockRouteHandler) AddAllowedIPs(string) error     { return nil }
func (m *mockRouteHandler) RemoveAllowedIPs() error        { return nil }

func generateBenchmarkData(tier benchmarkTier) (*peer.Status, map[route.ID]*route.Route) {
	statusRecorder := peer.NewRecorder("test-mgm")
	routes := make(map[route.ID]*route.Route)

	peerKeys := make([]string, tier.peers)
	for i := 0; i < tier.peers; i++ {
		peerKey := fmt.Sprintf("peer-%d", i)
		peerKeys[i] = peerKey
		fqdn := fmt.Sprintf("peer-%d.example.com", i)
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)

		err := statusRecorder.AddPeer(peerKey, fqdn, ip)
		if err != nil {
			panic(fmt.Sprintf("failed to add peer: %v", err))
		}

		var status peer.ConnStatus
		var latency time.Duration
		relayed := false

		switch i % 10 {
		case 0, 1: // 20% disconnected
			status = peer.StatusConnecting
			latency = 0
		case 2: // 10% idle
			status = peer.StatusIdle
			latency = 50 * time.Millisecond
		case 3, 4: // 20% relayed
			status = peer.StatusConnected
			relayed = true
			latency = time.Duration(50+i%100) * time.Millisecond
		default: // 50% direct connection
			status = peer.StatusConnected
			latency = time.Duration(10+i%40) * time.Millisecond
		}

		// Update peer state
		state := peer.State{
			PubKey:           peerKey,
			IP:               ip,
			FQDN:             fqdn,
			ConnStatus:       status,
			ConnStatusUpdate: time.Now(),
			Relayed:          relayed,
			Latency:          latency,
			Mux:              &sync.RWMutex{},
		}

		err = statusRecorder.UpdatePeerState(state)
		if err != nil {
			panic(fmt.Sprintf("failed to update peer state: %v", err))
		}
	}

	routeID := 0
	for i := 0; i < tier.routes; i++ {
		network := fmt.Sprintf("192.168.%d.0/24", i%256)
		prefix := netip.MustParsePrefix(network)

		haGroupSize := 1
		if i%4 == 0 { // 25% of routes have HA
			haGroupSize = tier.haPeersPerGroup
		}

		for j := 0; j < haGroupSize; j++ {
			peerIndex := (i*tier.haPeersPerGroup + j) % tier.peers
			peerKey := peerKeys[peerIndex]

			rID := route.ID(fmt.Sprintf("route-%d-%d", i, j))

			metric := 100 + j*10

			routes[rID] = &route.Route{
				ID:      rID,
				Network: prefix,
				Peer:    peerKey,
				Metric:  metric,
				NetID:   route.NetID(fmt.Sprintf("net-%d", i)),
			}
			routeID++
		}
	}

	return statusRecorder, routes
}

// Benchmark the optimized recalculate routes
func BenchmarkRecalculateRoutes(b *testing.B) {
	for _, tier := range benchmarkTiers {
		b.Run(tier.name, func(b *testing.B) {
			statusRecorder, routes := generateBenchmarkData(tier)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			watcher := &Watcher{
				ctx:                 ctx,
				statusRecorder:      statusRecorder,
				routes:              routes,
				routePeersNotifiers: make(map[string]chan struct{}),
				routeUpdate:         make(chan RoutesUpdate),
				peerStateUpdate:     make(chan struct{}),
				handler:             &mockRouteHandler{network: "benchmark"},
				currentChosenStatus: nil,
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := watcher.recalculateRoutes(reasonPeerUpdate, nil)
				if err != nil {
					b.Fatalf("recalculateRoutes failed: %v", err)
				}
			}
		})
	}
}
