package types_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/types"
)

type benchmarkScale struct {
	name   string
	peers  int
	groups int
}

var defaultScales = []benchmarkScale{
	{"100peers_5groups", 100, 5},
	{"500peers_20groups", 500, 20},
	{"1000peers_50groups", 1000, 50},
	{"5000peers_100groups", 5000, 100},
	{"10000peers_200groups", 10000, 200},
	{"20000peers_200groups", 20000, 200},
	{"30000peers_300groups", 30000, 300},
}

func skipCIBenchmark(b *testing.B) {
	if os.Getenv("CI") == "true" {
		b.Skip("Skipping benchmark in CI")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Single Peer Network Map Generation
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_Components benchmarks the components-based approach for a single peer.
func BenchmarkNetworkMapGeneration_Components(b *testing.B) {
	skipCIBenchmark(b)
	for _, scale := range defaultScales {
		b.Run(scale.name, func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
			ctx := context.Background()
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetPeerNetworkMapFromComponents(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// All Peers (UpdateAccountPeers hot path)
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_AllPeers benchmarks generating network maps for ALL peers.
func BenchmarkNetworkMapGeneration_AllPeers(b *testing.B) {
	skipCIBenchmark(b)
	scales := []benchmarkScale{
		{"100peers_5groups", 100, 5},
		{"500peers_20groups", 500, 20},
		{"1000peers_50groups", 1000, 50},
		{"5000peers_100groups", 5000, 100},
	}

	for _, scale := range scales {
		account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
		ctx := context.Background()

		peerIDs := make([]string, 0, len(account.Peers))
		for peerID := range account.Peers {
			peerIDs = append(peerIDs, peerID)
		}

		b.Run("components/"+scale.name, func(b *testing.B) {
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for _, peerID := range peerIDs {
					_ = account.GetPeerNetworkMapFromComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
				}
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Sub-operations
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_ComponentsCreation benchmarks components extraction.
func BenchmarkNetworkMapGeneration_ComponentsCreation(b *testing.B) {
	skipCIBenchmark(b)
	for _, scale := range defaultScales {
		b.Run(scale.name, func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
			ctx := context.Background()
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetPeerNetworkMapComponents(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, groupIDToUserIDs)
			}
		})
	}
}

// BenchmarkNetworkMapGeneration_ComponentsCalculation benchmarks calculation from pre-built components.
func BenchmarkNetworkMapGeneration_ComponentsCalculation(b *testing.B) {
	skipCIBenchmark(b)
	for _, scale := range defaultScales {
		b.Run(scale.name, func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
			ctx := context.Background()
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			components := account.GetPeerNetworkMapComponents(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, groupIDToUserIDs)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = types.CalculateNetworkMapFromComponents(ctx, components)
			}
		})
	}
}

// BenchmarkNetworkMapGeneration_PrecomputeMaps benchmarks precomputed map costs.
func BenchmarkNetworkMapGeneration_PrecomputeMaps(b *testing.B) {
	skipCIBenchmark(b)
	for _, scale := range defaultScales {
		b.Run("ResourcePoliciesMap/"+scale.name, func(b *testing.B) {
			account, _ := scalableTestAccount(scale.peers, scale.groups)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetResourcePoliciesMap()
			}
		})
		b.Run("ResourceRoutersMap/"+scale.name, func(b *testing.B) {
			account, _ := scalableTestAccount(scale.peers, scale.groups)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetResourceRoutersMap()
			}
		})
		b.Run("ActiveGroupUsers/"+scale.name, func(b *testing.B) {
			account, _ := scalableTestAccount(scale.peers, scale.groups)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetActiveGroupUsers()
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Scaling Analysis
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_GroupScaling tests group count impact on performance.
func BenchmarkNetworkMapGeneration_GroupScaling(b *testing.B) {
	skipCIBenchmark(b)
	groupCounts := []int{1, 5, 20, 50, 100, 200, 500}
	for _, numGroups := range groupCounts {
		b.Run(fmt.Sprintf("components_%dgroups", numGroups), func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(1000, numGroups)
			ctx := context.Background()
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetPeerNetworkMapFromComponents(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
			}
		})
	}
}

// BenchmarkNetworkMapGeneration_PeerScaling tests peer count impact on performance.
func BenchmarkNetworkMapGeneration_PeerScaling(b *testing.B) {
	skipCIBenchmark(b)
	peerCounts := []int{50, 100, 500, 1000, 2000, 5000, 10000, 20000, 30000}
	for _, numPeers := range peerCounts {
		numGroups := numPeers / 20
		if numGroups < 1 {
			numGroups = 1
		}
		b.Run(fmt.Sprintf("components_%dpeers", numPeers), func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(numPeers, numGroups)
			ctx := context.Background()
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = account.GetPeerNetworkMapFromComponents(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
			}
		})
	}
}
