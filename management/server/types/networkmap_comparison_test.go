package types

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/route"
)

func TestNetworkMapComponents_CompareWithLegacy(t *testing.T) {
	account := createTestAccount()
	ctx := context.Background()

	peerID := testingPeerID
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		pid := fmt.Sprintf("peer-%d", i)
		if pid == offlinePeerID {
			continue
		}
		validatedPeersMap[pid] = struct{}{}
	}

	peersCustomZone := nbdns.CustomZone{}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	legacyNetworkMap := account.GetPeerNetworkMap(
		ctx,
		peerID,
		peersCustomZone,
		validatedPeersMap,
		resourcePolicies,
		routers,
		nil,
		groupIDToUserIDs,
	)

	components := account.GetPeerNetworkMapComponents(
		ctx,
		peerID,
		peersCustomZone,
		validatedPeersMap,
		resourcePolicies,
		routers,
		groupIDToUserIDs,
	)

	if components == nil {
		t.Fatal("GetPeerNetworkMapComponents returned nil")
	}

	newNetworkMap := CalculateNetworkMapFromComponents(ctx, components)

	if newNetworkMap == nil {
		t.Fatal("CalculateNetworkMapFromComponents returned nil")
	}

	compareNetworkMaps(t, legacyNetworkMap, newNetworkMap)
}

func TestNetworkMapComponents_GoldenFileComparison(t *testing.T) {
	account := createTestAccount()
	ctx := context.Background()

	peerID := testingPeerID
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		pid := fmt.Sprintf("peer-%d", i)
		if pid == offlinePeerID {
			continue
		}
		validatedPeersMap[pid] = struct{}{}
	}

	peersCustomZone := nbdns.CustomZone{}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	legacyNetworkMap := account.GetPeerNetworkMap(
		ctx,
		peerID,
		peersCustomZone,
		validatedPeersMap,
		resourcePolicies,
		routers,
		nil,
		groupIDToUserIDs,
	)

	components := account.GetPeerNetworkMapComponents(
		ctx,
		peerID,
		peersCustomZone,
		validatedPeersMap,
		resourcePolicies,
		routers,
		groupIDToUserIDs,
	)

	require.NotNil(t, components, "GetPeerNetworkMapComponents returned nil")

	newNetworkMap := CalculateNetworkMapFromComponents(ctx, components)
	require.NotNil(t, newNetworkMap, "CalculateNetworkMapFromComponents returned nil")

	normalizeAndSortNetworkMap(legacyNetworkMap)
	normalizeAndSortNetworkMap(newNetworkMap)

	componentsJSON, err := json.MarshalIndent(components, "", "  ")
	require.NoError(t, err, "error marshaling components to JSON")

	legacyJSON, err := json.MarshalIndent(legacyNetworkMap, "", "  ")
	require.NoError(t, err, "error marshaling legacy network map to JSON")

	newJSON, err := json.MarshalIndent(newNetworkMap, "", "  ")
	require.NoError(t, err, "error marshaling new network map to JSON")

	goldenDir := filepath.Join("testdata", "comparison")
	err = os.MkdirAll(goldenDir, 0755)
	require.NoError(t, err)

	legacyGoldenPath := filepath.Join(goldenDir, "legacy_networkmap.json")
	err = os.WriteFile(legacyGoldenPath, legacyJSON, 0644)
	require.NoError(t, err, "error writing legacy golden file")

	newGoldenPath := filepath.Join(goldenDir, "components_networkmap.json")
	err = os.WriteFile(newGoldenPath, newJSON, 0644)
	require.NoError(t, err, "error writing components golden file")

	componentsPath := filepath.Join(goldenDir, "components.json")
	err = os.WriteFile(componentsPath, componentsJSON, 0644)
	require.NoError(t, err, "error writing components golden file")

	require.JSONEq(t, string(legacyJSON), string(newJSON),
		"NetworkMaps from legacy and components approaches do not match.\n"+
			"Legacy JSON saved to: %s\n"+
			"Components JSON saved to: %s",
		legacyGoldenPath, newGoldenPath)

	t.Logf("✅ NetworkMaps are identical")
	t.Logf("   Legacy NetworkMap: %s", legacyGoldenPath)
	t.Logf("   Components NetworkMap: %s", newGoldenPath)
}

func normalizeAndSortNetworkMap(nm *NetworkMap) {
	if nm == nil {
		return
	}

	sort.Slice(nm.Peers, func(i, j int) bool {
		return nm.Peers[i].ID < nm.Peers[j].ID
	})

	sort.Slice(nm.OfflinePeers, func(i, j int) bool {
		return nm.OfflinePeers[i].ID < nm.OfflinePeers[j].ID
	})

	sort.Slice(nm.Routes, func(i, j int) bool {
		return string(nm.Routes[i].ID) < string(nm.Routes[j].ID)
	})

	sort.Slice(nm.FirewallRules, func(i, j int) bool {
		if nm.FirewallRules[i].PeerIP != nm.FirewallRules[j].PeerIP {
			return nm.FirewallRules[i].PeerIP < nm.FirewallRules[j].PeerIP
		}
		if nm.FirewallRules[i].Direction != nm.FirewallRules[j].Direction {
			return nm.FirewallRules[i].Direction < nm.FirewallRules[j].Direction
		}
		return nm.FirewallRules[i].Protocol < nm.FirewallRules[j].Protocol
	})

	for i := range nm.RoutesFirewallRules {
		sort.Strings(nm.RoutesFirewallRules[i].SourceRanges)
	}

	sort.Slice(nm.RoutesFirewallRules, func(i, j int) bool {
		if nm.RoutesFirewallRules[i].Destination != nm.RoutesFirewallRules[j].Destination {
			return nm.RoutesFirewallRules[i].Destination < nm.RoutesFirewallRules[j].Destination
		}

		minLen := len(nm.RoutesFirewallRules[i].SourceRanges)
		if len(nm.RoutesFirewallRules[j].SourceRanges) < minLen {
			minLen = len(nm.RoutesFirewallRules[j].SourceRanges)
		}
		for k := 0; k < minLen; k++ {
			if nm.RoutesFirewallRules[i].SourceRanges[k] != nm.RoutesFirewallRules[j].SourceRanges[k] {
				return nm.RoutesFirewallRules[i].SourceRanges[k] < nm.RoutesFirewallRules[j].SourceRanges[k]
			}
		}
		if len(nm.RoutesFirewallRules[i].SourceRanges) != len(nm.RoutesFirewallRules[j].SourceRanges) {
			return len(nm.RoutesFirewallRules[i].SourceRanges) < len(nm.RoutesFirewallRules[j].SourceRanges)
		}

		return string(nm.RoutesFirewallRules[i].RouteID) < string(nm.RoutesFirewallRules[j].RouteID)
	})

	if nm.DNSConfig.CustomZones != nil {
		for i := range nm.DNSConfig.CustomZones {
			sort.Slice(nm.DNSConfig.CustomZones[i].Records, func(a, b int) bool {
				return nm.DNSConfig.CustomZones[i].Records[a].Name < nm.DNSConfig.CustomZones[i].Records[b].Name
			})
		}
	}
}

func compareNetworkMaps(t *testing.T, legacy, new *NetworkMap) {
	t.Helper()

	if legacy.Network.Serial != new.Network.Serial {
		t.Errorf("Network Serial mismatch: legacy=%d, new=%d", legacy.Network.Serial, new.Network.Serial)
	}

	if len(legacy.Peers) != len(new.Peers) {
		t.Errorf("Peers count mismatch: legacy=%d, new=%d", len(legacy.Peers), len(new.Peers))
	}

	legacyPeerIDs := make(map[string]bool)
	for _, p := range legacy.Peers {
		legacyPeerIDs[p.ID] = true
	}

	for _, p := range new.Peers {
		if !legacyPeerIDs[p.ID] {
			t.Errorf("New NetworkMap contains peer %s not in legacy", p.ID)
		}
	}

	if len(legacy.OfflinePeers) != len(new.OfflinePeers) {
		t.Errorf("OfflinePeers count mismatch: legacy=%d, new=%d", len(legacy.OfflinePeers), len(new.OfflinePeers))
	}

	if len(legacy.FirewallRules) != len(new.FirewallRules) {
		t.Logf("FirewallRules count mismatch: legacy=%d, new=%d", len(legacy.FirewallRules), len(new.FirewallRules))
	}

	if len(legacy.Routes) != len(new.Routes) {
		t.Logf("Routes count mismatch: legacy=%d, new=%d", len(legacy.Routes), len(new.Routes))
	}

	if len(legacy.RoutesFirewallRules) != len(new.RoutesFirewallRules) {
		t.Logf("RoutesFirewallRules count mismatch: legacy=%d, new=%d", len(legacy.RoutesFirewallRules), len(new.RoutesFirewallRules))
	}

	if legacy.DNSConfig.ServiceEnable != new.DNSConfig.ServiceEnable {
		t.Errorf("DNSConfig.ServiceEnable mismatch: legacy=%v, new=%v", legacy.DNSConfig.ServiceEnable, new.DNSConfig.ServiceEnable)
	}
}

const (
	numPeers          = 100
	devGroupID        = "group-dev"
	opsGroupID        = "group-ops"
	allGroupID        = "group-all"
	routeID           = route.ID("route-main")
	routeHA1ID        = route.ID("route-ha-1")
	routeHA2ID        = route.ID("route-ha-2")
	policyIDDevOps    = "policy-dev-ops"
	policyIDAll       = "policy-all"
	policyIDPosture   = "policy-posture"
	policyIDDrop      = "policy-drop"
	postureCheckID    = "posture-check-ver"
	networkResourceID = "res-database"
	networkID         = "net-database"
	networkRouterID   = "router-database"
	nameserverGroupID = "ns-group-main"
	testingPeerID     = "peer-60"
	expiredPeerID     = "peer-98"
	offlinePeerID     = "peer-99"
	routingPeerID     = "peer-95"
	testAccountID     = "account-comparison-test"
)

func createTestAccount() *Account {
	peers := make(map[string]*nbpeer.Peer)
	devGroupPeers, opsGroupPeers, allGroupPeers := []string{}, []string{}, []string{}

	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		ip := net.IP{100, 64, 0, byte(i + 1)}
		wtVersion := "0.25.0"
		if i%2 == 0 {
			wtVersion = "0.40.0"
		}

		p := &nbpeer.Peer{
			ID: peerID, IP: ip, Key: fmt.Sprintf("key-%s", peerID), DNSLabel: fmt.Sprintf("peer%d", i+1),
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
			UserID: "user-admin", Meta: nbpeer.PeerSystemMeta{WtVersion: wtVersion, GoOS: "linux"},
		}

		if peerID == expiredPeerID {
			p.LoginExpirationEnabled = true
			pastTimestamp := time.Now().Add(-2 * time.Hour)
			p.LastLogin = &pastTimestamp
		}

		peers[peerID] = p
		allGroupPeers = append(allGroupPeers, peerID)
		if i < numPeers/2 {
			devGroupPeers = append(devGroupPeers, peerID)
		} else {
			opsGroupPeers = append(opsGroupPeers, peerID)
		}
	}

	groups := map[string]*Group{
		allGroupID: {ID: allGroupID, Name: "All", Peers: allGroupPeers},
		devGroupID: {ID: devGroupID, Name: "Developers", Peers: devGroupPeers},
		opsGroupID: {ID: opsGroupID, Name: "Operations", Peers: opsGroupPeers},
	}

	policies := []*Policy{
		{
			ID: policyIDAll, Name: "Default-Allow", Enabled: true,
			Rules: []*PolicyRule{{
				ID: policyIDAll, Name: "Allow All", Enabled: true, Action: PolicyTrafficActionAccept,
				Protocol: PolicyRuleProtocolALL, Bidirectional: true,
				Sources: []string{allGroupID}, Destinations: []string{allGroupID},
			}},
		},
		{
			ID: policyIDDevOps, Name: "Dev to Ops Web Access", Enabled: true,
			Rules: []*PolicyRule{{
				ID: policyIDDevOps, Name: "Dev -> Ops (HTTP Range)", Enabled: true, Action: PolicyTrafficActionAccept,
				Protocol: PolicyRuleProtocolTCP, Bidirectional: false,
				PortRanges: []RulePortRange{{Start: 8080, End: 8090}},
				Sources:    []string{devGroupID}, Destinations: []string{opsGroupID},
			}},
		},
		{
			ID: policyIDDrop, Name: "Drop DB traffic", Enabled: true,
			Rules: []*PolicyRule{{
				ID: policyIDDrop, Name: "Drop DB", Enabled: true, Action: PolicyTrafficActionDrop,
				Protocol: PolicyRuleProtocolTCP, Ports: []string{"5432"}, Bidirectional: true,
				Sources: []string{devGroupID}, Destinations: []string{opsGroupID},
			}},
		},
		{
			ID: policyIDPosture, Name: "Posture Check for DB Resource", Enabled: true,
			SourcePostureChecks: []string{postureCheckID},
			Rules: []*PolicyRule{{
				ID: policyIDPosture, Name: "Allow DB Access", Enabled: true, Action: PolicyTrafficActionAccept,
				Protocol: PolicyRuleProtocolALL, Bidirectional: true,
				Sources: []string{opsGroupID}, DestinationResource: Resource{ID: networkResourceID},
			}},
		},
	}

	routes := map[route.ID]*route.Route{
		routeID: {
			ID: routeID, Network: netip.MustParsePrefix("192.168.10.0/24"),
			Peer:        peers["peer-75"].Key,
			PeerID:      "peer-75",
			Description: "Route to internal resource", Enabled: true,
			PeerGroups:          []string{devGroupID, opsGroupID},
			Groups:              []string{devGroupID, opsGroupID},
			AccessControlGroups: []string{devGroupID},
		},
		routeHA1ID: {
			ID: routeHA1ID, Network: netip.MustParsePrefix("10.10.0.0/16"),
			Peer:        peers["peer-80"].Key,
			PeerID:      "peer-80",
			Description: "HA Route 1", Enabled: true, Metric: 1000,
			PeerGroups:          []string{allGroupID},
			Groups:              []string{allGroupID},
			AccessControlGroups: []string{allGroupID},
		},
		routeHA2ID: {
			ID: routeHA2ID, Network: netip.MustParsePrefix("10.10.0.0/16"),
			Peer:        peers["peer-90"].Key,
			PeerID:      "peer-90",
			Description: "HA Route 2", Enabled: true, Metric: 900,
			PeerGroups:          []string{devGroupID, opsGroupID},
			Groups:              []string{devGroupID, opsGroupID},
			AccessControlGroups: []string{allGroupID},
		},
	}

	account := &Account{
		Id: testAccountID, Peers: peers, Groups: groups, Policies: policies, Routes: routes,
		Network: &Network{
			Identifier: "net-comparison-test", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(16, 32)}, Serial: 1,
		},
		DNSSettings: DNSSettings{DisabledManagementGroups: []string{opsGroupID}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			nameserverGroupID: {
				ID: nameserverGroupID, Name: "Main NS", Enabled: true, Groups: []string{devGroupID},
				NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53}},
			},
		},
		PostureChecks: []*posture.Checks{
			{ID: postureCheckID, Name: "Check version", Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.26.0"},
			}},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{ID: networkResourceID, NetworkID: networkID, AccountID: testAccountID, Enabled: true, Address: "db.netbird.cloud"},
		},
		Networks: []*networkTypes.Network{{ID: networkID, Name: "DB Network", AccountID: testAccountID}},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{ID: networkRouterID, NetworkID: networkID, Peer: routingPeerID, Enabled: true, AccountID: testAccountID},
		},
		Settings: &Settings{PeerLoginExpirationEnabled: true, PeerLoginExpiration: 1 * time.Hour},
	}

	for _, p := range account.Policies {
		p.AccountID = account.Id
	}
	for _, r := range account.Routes {
		r.AccountID = account.Id
	}

	return account
}

func BenchmarkLegacyNetworkMap(b *testing.B) {
	account := createTestAccount()
	ctx := context.Background()
	peerID := testingPeerID
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		pid := fmt.Sprintf("peer-%d", i)
		if pid != offlinePeerID {
			validatedPeersMap[pid] = struct{}{}
		}
	}

	peersCustomZone := nbdns.CustomZone{}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = account.GetPeerNetworkMap(
			ctx,
			peerID,
			peersCustomZone,
			validatedPeersMap,
			resourcePolicies,
			routers,
			nil,
			groupIDToUserIDs,
		)
	}
}

func BenchmarkComponentsNetworkMap(b *testing.B) {
	account := createTestAccount()
	ctx := context.Background()
	peerID := testingPeerID
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		pid := fmt.Sprintf("peer-%d", i)
		if pid != offlinePeerID {
			validatedPeersMap[pid] = struct{}{}
		}
	}

	peersCustomZone := nbdns.CustomZone{}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		components := account.GetPeerNetworkMapComponents(
			ctx,
			peerID,
			peersCustomZone,
			validatedPeersMap,
			resourcePolicies,
			routers,
			groupIDToUserIDs,
		)
		_ = CalculateNetworkMapFromComponents(ctx, components)
	}
}

func BenchmarkComponentsCreation(b *testing.B) {
	account := createTestAccount()
	ctx := context.Background()
	peerID := testingPeerID
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		pid := fmt.Sprintf("peer-%d", i)
		if pid != offlinePeerID {
			validatedPeersMap[pid] = struct{}{}
		}
	}

	peersCustomZone := nbdns.CustomZone{}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = account.GetPeerNetworkMapComponents(
			ctx,
			peerID,
			peersCustomZone,
			validatedPeersMap,
			resourcePolicies,
			routers,
			groupIDToUserIDs,
		)
	}
}

func BenchmarkCalculationFromComponents(b *testing.B) {
	account := createTestAccount()
	ctx := context.Background()
	peerID := testingPeerID
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		pid := fmt.Sprintf("peer-%d", i)
		if pid != offlinePeerID {
			validatedPeersMap[pid] = struct{}{}
		}
	}

	peersCustomZone := nbdns.CustomZone{}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	components := account.GetPeerNetworkMapComponents(
		ctx,
		peerID,
		peersCustomZone,
		validatedPeersMap,
		resourcePolicies,
		routers,
		groupIDToUserIDs,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateNetworkMapFromComponents(ctx, components)
	}
}

func TestGetPeerNetworkMap_ProdAccount_CompareImplementations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	testAccount := loadProdAccountFromJSON(t)

	testingPeerID := "cq3526bl0ubs73bbtpbg"
	require.Contains(t, testAccount.Peers, testingPeerID, "Testing peer should exist in account")

	validatedPeersMap := make(map[string]struct{})
	for peerID := range testAccount.Peers {
		validatedPeersMap[peerID] = struct{}{}
	}

	resourcePolicies := testAccount.GetResourcePoliciesMap()
	routers := testAccount.GetResourceRoutersMap()
	groupIDToUserIDs := testAccount.GetActiveGroupUsers()

	legacyNetworkMap := testAccount.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs)
	require.NotNil(t, legacyNetworkMap, "GetPeerNetworkMap returned nil")

	components := testAccount.GetPeerNetworkMapComponents(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, groupIDToUserIDs)
	require.NotNil(t, components, "GetPeerNetworkMapComponents returned nil")

	newNetworkMap := CalculateNetworkMapFromComponents(ctx, components)
	require.NotNil(t, newNetworkMap, "CalculateNetworkMapFromComponents returned nil")

	normalizeAndSortNetworkMap(legacyNetworkMap)
	normalizeAndSortNetworkMap(newNetworkMap)

	componentsJSON, err := json.MarshalIndent(components, "", "  ")
	require.NoError(t, err, "error marshaling components to JSON")

	legacyJSON, err := json.MarshalIndent(legacyNetworkMap, "", "  ")
	require.NoError(t, err, "error marshaling legacy network map to JSON")

	newJSON, err := json.MarshalIndent(newNetworkMap, "", "  ")
	require.NoError(t, err, "error marshaling new network map to JSON")

	outputDir := filepath.Join("testdata", fmt.Sprintf("compare_peer_%s", testingPeerID))
	err = os.MkdirAll(outputDir, 0755)
	require.NoError(t, err)

	legacyFilePath := filepath.Join(outputDir, "legacy_networkmap.json")
	err = os.WriteFile(legacyFilePath, legacyJSON, 0644)
	require.NoError(t, err)

	componentsPath := filepath.Join(outputDir, "components.json")
	err = os.WriteFile(componentsPath, componentsJSON, 0644)
	require.NoError(t, err)

	newFilePath := filepath.Join(outputDir, "components_networkmap.json")
	err = os.WriteFile(newFilePath, newJSON, 0644)
	require.NoError(t, err)

	t.Logf("Files saved to:\n  Legacy NetworkMap: %s\n  Components: %s\n  Components NetworkMap: %s",
		legacyFilePath, componentsPath, newFilePath)

	require.JSONEq(t, string(legacyJSON), string(newJSON),
		"NetworkMaps from legacy and components approaches do not match for peer %s.\n"+
			"Legacy JSON saved to: %s\n"+
			"Components JSON saved to: %s\n"+
			"Components NetworkMap saved to: %s",
		testingPeerID, legacyFilePath, componentsPath, newFilePath)

	t.Logf("✅ NetworkMaps are identical for peer %s", testingPeerID)
}

func loadProdAccountFromJSON(t testing.TB) *Account {
	t.Helper()

	testDataPath := filepath.Join("testdata", "account_cnlf3j3l0ubs738o5d4g.json")
	data, err := os.ReadFile(testDataPath)
	require.NoError(t, err, "Failed to read prod account JSON file")

	var account Account
	err = json.Unmarshal(data, &account)
	require.NoError(t, err, "Failed to unmarshal prod account")

	if account.Groups == nil {
		account.Groups = make(map[string]*Group)
	}
	if account.Peers == nil {
		account.Peers = make(map[string]*nbpeer.Peer)
	}
	if account.Policies == nil {
		account.Policies = []*Policy{}
	}

	return &account
}

func BenchmarkGetPeerNetworkMapCompactCached(b *testing.B) {
	account := loadProdAccountFromJSON(b)

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{}, len(account.Peers))
	for _, peer := range account.Peers {
		validatedPeersMap[peer.ID] = struct{}{}
	}
	dnsDomain := account.Settings.DNSDomain
	customZone := account.GetPeersCustomZone(ctx, dnsDomain)

	builder := NewNetworkMapBuilder(account, validatedPeersMap)

	testingPeerID := "d3knp53l0ubs738a3n6g"

	regularNm := builder.GetPeerNetworkMap(ctx, testingPeerID, customZone, validatedPeersMap, nil)
	compactNm := builder.GetPeerNetworkMapCompact(ctx, testingPeerID, customZone, validatedPeersMap, nil)
	compactCachedNm := builder.GetPeerNetworkMapCompactCached(ctx, testingPeerID, customZone, validatedPeersMap, nil)

	regularJSON, err := json.Marshal(regularNm)
	require.NoError(b, err)

	compactJSON, err := json.Marshal(compactNm)
	require.NoError(b, err)

	compactCachedJSON, err := json.Marshal(compactCachedNm)
	require.NoError(b, err)

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	agUsers := account.GetActiveGroupUsers()
	components := account.GetPeerNetworkMapComponents(ctx, testingPeerID, customZone, validatedPeersMap, resourcePolicies, routers, agUsers)
	componentsJSON, err := json.Marshal(components)
	require.NoError(b, err)

	regularSize := len(regularJSON)
	compactSize := len(compactJSON)
	compactCachedSize := len(compactCachedJSON)
	componentsSize := len(componentsJSON)

	compactSavingsPercent := 100 - int(float64(compactCachedSize)/float64(regularSize)*100)
	componentsSavingsPercent := 100 - int(float64(componentsSize)/float64(regularSize)*100)

	b.ReportMetric(float64(regularSize), "regular_bytes")
	b.ReportMetric(float64(compactCachedSize), "compact_cached_bytes")
	b.ReportMetric(float64(componentsSize), "components_bytes")
	b.ReportMetric(float64(compactSavingsPercent), "compact_savings_%")
	b.ReportMetric(float64(componentsSavingsPercent), "components_savings_%")

	b.Logf("========== Network Map Size Comparison ==========")
	b.Logf("Regular network map:       %d bytes", regularSize)
	b.Logf("Compact network map:       %d bytes (-%d%%)", compactSize, 100-int(float64(compactSize)/float64(regularSize)*100))
	b.Logf("Compact cached network map: %d bytes (-%d%%)", compactCachedSize, compactSavingsPercent)
	b.Logf("Components:                %d bytes (-%d%%)", componentsSize, componentsSavingsPercent)
	b.Logf("")
	b.Logf("Bandwidth savings (Compact cached): %d bytes saved (%d%%)", regularSize-compactCachedSize, compactSavingsPercent)
	b.Logf("Bandwidth savings (Components):     %d bytes saved (%d%%)", regularSize-componentsSize, componentsSavingsPercent)
	b.Logf("=================================================")

	b.Run("Legacy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = account.GetPeerNetworkMap(ctx, testingPeerID, customZone, validatedPeersMap, resourcePolicies, routers, nil, agUsers)
		}
	})
	b.Run("LegacyCompacted", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = account.GetPeerNetworkMapCompacted(ctx, testingPeerID, customZone, validatedPeersMap, resourcePolicies, routers, nil, agUsers)
		}
	})

	b.Run("ComponentsNetworkMap", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			components := account.GetPeerNetworkMapComponents(
				ctx,
				testingPeerID,
				customZone,
				validatedPeersMap,
				resourcePolicies,
				routers,
				agUsers,
			)
			_ = CalculateNetworkMapFromComponents(ctx, components)
		}
	})

	b.Run("ComponentsCreation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = account.GetPeerNetworkMapComponents(
				ctx,
				testingPeerID,
				customZone,
				validatedPeersMap,
				resourcePolicies,
				routers,
				agUsers,
			)
		}
	})

	b.Run("CalculationFromComponents", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = CalculateNetworkMapFromComponents(ctx, components)
		}
	})

	b.Run("CachedAsIs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = builder.GetPeerNetworkMap(ctx, testingPeerID, customZone, validatedPeersMap, nil)
		}
	})

	b.Run("CachedAsIsAndCompacted", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = builder.GetPeerNetworkMapCompact(ctx, testingPeerID, customZone, validatedPeersMap, nil)
		}
	})

	b.Run("CachedCompacted", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = builder.GetPeerNetworkMapCompactCached(ctx, testingPeerID, customZone, validatedPeersMap, nil)
		}
	})
}
