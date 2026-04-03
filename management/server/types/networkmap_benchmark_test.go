package types_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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

// ──────────────────────────────────────────────────────────────────────────────
// Single Peer Network Map Generation
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_Legacy benchmarks the legacy GetPeerNetworkMap for a single peer.
func BenchmarkNetworkMapGeneration_Legacy(b *testing.B) {
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
				_ = account.GetPeerNetworkMap(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
			}
		})
	}
}

// BenchmarkNetworkMapGeneration_Components benchmarks the components-based approach for a single peer.
func BenchmarkNetworkMapGeneration_Components(b *testing.B) {
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

// BenchmarkNetworkMapGeneration_Builder benchmarks the builder approach for a single peer.
func BenchmarkNetworkMapGeneration_Builder(b *testing.B) {
	for _, scale := range defaultScales {
		b.Run(scale.name, func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
			ctx := context.Background()
			builder := types.NewNetworkMapBuilder(account, validatedPeers)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = builder.GetPeerNetworkMap(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, nil)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// All Peers (UpdateAccountPeers hot path)
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_AllPeers benchmarks generating network maps for ALL peers.
func BenchmarkNetworkMapGeneration_AllPeers(b *testing.B) {
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

		b.Run("legacy/"+scale.name, func(b *testing.B) {
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for _, peerID := range peerIDs {
					_ = account.GetPeerNetworkMap(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
				}
			}
		})

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

		b.Run("builder/"+scale.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				builder := types.NewNetworkMapBuilder(account, validatedPeers)
				for _, peerID := range peerIDs {
					_ = builder.GetPeerNetworkMap(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, nil)
				}
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Sub-operations
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_BuilderInit benchmarks builder cache initialization.
func BenchmarkNetworkMapGeneration_BuilderInit(b *testing.B) {
	for _, scale := range defaultScales {
		b.Run(scale.name, func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = types.NewNetworkMapBuilder(account, validatedPeers)
			}
		})
	}
}

// BenchmarkNetworkMapGeneration_ComponentsCreation benchmarks components extraction.
func BenchmarkNetworkMapGeneration_ComponentsCreation(b *testing.B) {
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

// BenchmarkNetworkMapGeneration_BuilderIncrementalAdd benchmarks incremental peer addition.
func BenchmarkNetworkMapGeneration_BuilderIncrementalAdd(b *testing.B) {
	for _, scale := range defaultScales {
		b.Run(scale.name, func(b *testing.B) {
			account, validatedPeers := scalableTestAccount(scale.peers, scale.groups)
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				builder := types.NewNetworkMapBuilder(account, validatedPeers)
				newPeerID := fmt.Sprintf("peer-new-%d", i)
				newPeer := &nbpeer.Peer{
					ID: newPeerID, IP: net.IP{100, 65, byte(i / 256), byte(i % 256)},
					Key: fmt.Sprintf("key-%s", newPeerID), DNSLabel: fmt.Sprintf("peernew%d", i),
					Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
					UserID: "user-admin", Meta: nbpeer.PeerSystemMeta{WtVersion: "0.40.0", GoOS: "linux"},
				}
				account.Peers[newPeerID] = newPeer
				account.Groups["group-all"].Peers = append(account.Groups["group-all"].Peers, newPeerID)
				validatedPeers[newPeerID] = struct{}{}
				_ = builder.OnPeerAddedIncremental(account, newPeerID)
				delete(account.Peers, newPeerID)
				account.Groups["group-all"].Peers = account.Groups["group-all"].Peers[:len(account.Groups["group-all"].Peers)-1]
				delete(validatedPeers, newPeerID)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Scaling Analysis
// ──────────────────────────────────────────────────────────────────────────────

// BenchmarkNetworkMapGeneration_GroupScaling tests group count impact on performance.
func BenchmarkNetworkMapGeneration_GroupScaling(b *testing.B) {
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
