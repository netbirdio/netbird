package types_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	goproto "google.golang.org/protobuf/proto"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// TestNetworkMapWireBreakdown is a one-shot diagnostic: it computes the wire
// size attributable to each top-level field of both the legacy NetworkMap and
// the components NetworkMapEnvelope at the 5000-peer scale, so the migration
// docs can attribute the size reduction to each optimization. Runs only on
// demand via -run TestNetworkMapWireBreakdown.
func TestNetworkMapWireBreakdown(t *testing.T) {
	if testing.Short() {
		t.Skip("size diagnostic, skipped with -short")
	}
	if os.Getenv("NB_RUN_WIRE_BREAKDOWN") != "1" {
		t.Skip("set NB_RUN_WIRE_BREAKDOWN=1 to run wire breakdown diagnostic")
	}

	const peerCount, groupCount = 5000, 100
	account, validatedPeers := scalableTestAccount(peerCount, groupCount)
	assignValidWgKeys(account)

	ctx := context.Background()
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	peerID := "peer-0"
	peer := account.Peers[peerID]
	networkMap := account.GetPeerNetworkMapFromComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil, groupIDToUserIDs)
	components := account.GetPeerNetworkMapComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, groupIDToUserIDs)

	dnsCache := &cache.DNSConfigCache{}
	settings := &types.Settings{}

	legacyResp := mgmtgrpc.ToSyncResponse(ctx, nil, nil, nil, peer, nil, nil, networkMap, "netbird.cloud", nil, dnsCache, settings, nil, nil, 0)
	legacyTotal := mustMarshalSize(t, legacyResp.NetworkMap)

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: components,
		PeerConfig: legacyResp.NetworkMap.PeerConfig,
		DNSDomain:  "netbird.cloud",
	})
	componentsTotal := mustMarshalSize(t, envelope)

	t.Logf("\n=== LEGACY NetworkMap (%d peers, %d groups) ===", peerCount, groupCount)
	t.Logf("  Total: %d bytes\n", legacyTotal)

	legacyBreakdown := []struct {
		name string
		nm   *proto.NetworkMap
	}{
		{"RemotePeers", &proto.NetworkMap{RemotePeers: legacyResp.NetworkMap.RemotePeers}},
		{"OfflinePeers", &proto.NetworkMap{OfflinePeers: legacyResp.NetworkMap.OfflinePeers}},
		{"FirewallRules", &proto.NetworkMap{FirewallRules: legacyResp.NetworkMap.FirewallRules}},
		{"Routes", &proto.NetworkMap{Routes: legacyResp.NetworkMap.Routes}},
		{"RoutesFirewallRules", &proto.NetworkMap{RoutesFirewallRules: legacyResp.NetworkMap.RoutesFirewallRules}},
		{"DNSConfig", &proto.NetworkMap{DNSConfig: legacyResp.NetworkMap.DNSConfig}},
		{"PeerConfig", &proto.NetworkMap{PeerConfig: legacyResp.NetworkMap.PeerConfig}},
		{"SshAuth", &proto.NetworkMap{SshAuth: legacyResp.NetworkMap.SshAuth}},
	}
	for _, e := range legacyBreakdown {
		size := mustMarshalSize(t, e.nm)
		t.Logf("  %-22s %8d bytes  %5.1f%%", e.name, size, pct(size, legacyTotal))
	}

	full := envelope.GetFull()
	if full == nil {
		t.Fatalf("expected full network map envelope payload, got nil")
	}
	t.Logf("\n=== COMPONENTS NetworkMapEnvelope (%d peers, %d groups) ===", peerCount, groupCount)
	t.Logf("  Total: %d bytes  (%.1f%% of legacy)\n", componentsTotal, pct(componentsTotal, legacyTotal))

	componentsBreakdown := []struct {
		name string
		nm   *proto.NetworkMapComponentsFull
	}{
		{"Peers", &proto.NetworkMapComponentsFull{Peers: full.Peers}},
		{"Policies", &proto.NetworkMapComponentsFull{Policies: full.Policies}},
		{"Groups", &proto.NetworkMapComponentsFull{Groups: full.Groups}},
		{"Routes (raw)", &proto.NetworkMapComponentsFull{Routes: full.Routes}},
		{"NameServerGroups", &proto.NetworkMapComponentsFull{NameserverGroups: full.NameserverGroups}},
		{"AllDNSRecords", &proto.NetworkMapComponentsFull{AllDnsRecords: full.AllDnsRecords}},
		{"AccountZones", &proto.NetworkMapComponentsFull{AccountZones: full.AccountZones}},
		{"NetworkResources", &proto.NetworkMapComponentsFull{NetworkResources: full.NetworkResources}},
		{"RoutersMap", &proto.NetworkMapComponentsFull{RoutersMap: full.RoutersMap}},
		{"ResourcePoliciesMap", &proto.NetworkMapComponentsFull{ResourcePoliciesMap: full.ResourcePoliciesMap}},
		{"GroupIDToUserIDs", &proto.NetworkMapComponentsFull{GroupIdToUserIds: full.GroupIdToUserIds}},
		{"AllowedUserIDs", &proto.NetworkMapComponentsFull{AllowedUserIds: full.AllowedUserIds}},
		{"PostureFailedPeers", &proto.NetworkMapComponentsFull{PostureFailedPeers: full.PostureFailedPeers}},
		{"DNSSettings", &proto.NetworkMapComponentsFull{DnsSettings: full.DnsSettings}},
		{"PeerConfig", &proto.NetworkMapComponentsFull{PeerConfig: full.PeerConfig}},
		{"AgentVersions", &proto.NetworkMapComponentsFull{AgentVersions: full.AgentVersions}},
	}
	for _, e := range componentsBreakdown {
		size := mustMarshalSize(t, e.nm)
		t.Logf("  %-22s %8d bytes  %5.1f%%", e.name, size, pct(size, componentsTotal))
	}

	t.Logf("\n=== Per-PeerCompact average ===")
	if len(full.Peers) > 0 {
		t.Logf("  PeerCompact avg: %d bytes/peer", mustMarshalSize(t, &proto.NetworkMapComponentsFull{Peers: full.Peers})/len(full.Peers))
	}
	if len(legacyResp.NetworkMap.RemotePeers) > 0 {
		t.Logf("  RemotePeer avg:  %d bytes/peer",
			mustMarshalSize(t, &proto.NetworkMap{RemotePeers: legacyResp.NetworkMap.RemotePeers})/len(legacyResp.NetworkMap.RemotePeers))
	}

	t.Logf("\n=== FirewallRule expansion footprint ===")
	t.Logf("  legacy FirewallRules count: %d", len(legacyResp.NetworkMap.FirewallRules))
	t.Logf("  components Policies count:  %d", len(full.Policies))
	t.Logf("  components Groups count:    %d", len(full.Groups))

	totalGroupPeerIdxs := 0
	for _, g := range full.Groups {
		totalGroupPeerIdxs += len(g.PeerIndexes)
	}
	t.Logf("  components peer-index refs across all groups: %d", totalGroupPeerIdxs)
}

func mustMarshalSize(t *testing.T, m goproto.Message) int {
	b, err := goproto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return len(b)
}

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
}

// Stops fmt being unused if the breakdown loop above is later commented out.
var _ = fmt.Sprintf
