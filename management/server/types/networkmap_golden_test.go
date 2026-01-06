package types_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// update flag is used to update the golden file.
// example: go test ./... -v -update
// var update = flag.Bool("update", false, "update golden files")

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
	testingPeerID     = "peer-60" // A peer from the "dev" group, should receive the most detailed map.
	expiredPeerID     = "peer-98" // This peer will be online but with an expired session.
	offlinePeerID     = "peer-99" // This peer will be completely offline.
	routingPeerID     = "peer-95" // This peer is used for routing, it has a route to the network.
	testAccountID     = "account-golden-test"
)

func TestGetPeerNetworkMap_Golden(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()

	networkMap := account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, nil, account.GetActiveGroupUsers())

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden.json")

	t.Log("Update golden file...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "resulted network map from OLD method does not match golden file")
}

func TestGetPeerNetworkMap_Golden_New(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)

		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)
	networkMap := builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_new.json")

	t.Log("Update golden file...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "resulted network map from NEW builder does not match golden file")
}

func BenchmarkGetPeerNetworkMap(b *testing.B) {
	account := createTestAccountWithEntities()
	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	var peerIDs []string
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		validatedPeersMap[peerID] = struct{}{}
		peerIDs = append(peerIDs, peerID)
	}

	b.ResetTimer()
	b.Run("old builder", func(b *testing.B) {
		for range b.N {
			for _, peerID := range peerIDs {
				_ = account.GetPeerNetworkMap(ctx, peerID, dns.CustomZone{}, validatedPeersMap, nil, nil, nil, account.GetActiveGroupUsers())
			}
		}
	})
	b.ResetTimer()
	b.Run("new builder", func(b *testing.B) {
		for range b.N {
			builder := types.NewNetworkMapBuilder(account, validatedPeersMap)
			for _, peerID := range peerIDs {
				_ = builder.GetPeerNetworkMap(ctx, peerID, dns.CustomZone{}, validatedPeersMap, nil)
			}
		}
	})
}

func TestGetPeerNetworkMap_Golden_WithNewPeer(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	newPeerID := "peer-new-101"
	newPeerIP := net.IP{100, 64, 1, 1}
	newPeer := &nbpeer.Peer{
		ID:        newPeerID,
		IP:        newPeerIP,
		Key:       fmt.Sprintf("key-%s", newPeerID),
		DNSLabel:  "peernew101",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:    "user-admin",
		Meta:      nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
		LastLogin: func() *time.Time { t := time.Now(); return &t }(),
	}

	account.Peers[newPeerID] = newPeer

	if devGroup, exists := account.Groups[devGroupID]; exists {
		devGroup.Peers = append(devGroup.Peers, newPeerID)
	}

	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = append(allGroup.Peers, newPeerID)
	}

	validatedPeersMap[newPeerID] = struct{}{}

	if account.Network != nil {
		account.Network.Serial++
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()

	networkMap := account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, nil, account.GetActiveGroupUsers())

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_with_new_peer.json")

	t.Log("Update golden file with new peer...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from OLD method with new peer does not match golden file")
}

func TestGetPeerNetworkMap_Golden_New_WithOnPeerAdded(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)

	newPeerID := "peer-new-101"
	newPeerIP := net.IP{100, 64, 1, 1}
	newPeer := &nbpeer.Peer{
		ID:        newPeerID,
		IP:        newPeerIP,
		Key:       fmt.Sprintf("key-%s", newPeerID),
		DNSLabel:  "peernew101",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:    "user-admin",
		Meta:      nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
		LastLogin: func() *time.Time { t := time.Now(); return &t }(),
	}

	account.Peers[newPeerID] = newPeer

	if devGroup, exists := account.Groups[devGroupID]; exists {
		devGroup.Peers = append(devGroup.Peers, newPeerID)
	}

	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = append(allGroup.Peers, newPeerID)
	}

	validatedPeersMap[newPeerID] = struct{}{}

	if account.Network != nil {
		account.Network.Serial++
	}

	err := builder.OnPeerAddedIncremental(account, newPeerID)
	require.NoError(t, err, "error adding peer to cache")

	networkMap := builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_new_with_onpeeradded.json")
	t.Log("Update golden file with OnPeerAdded...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from NEW builder with OnPeerAdded does not match golden file")
}

func BenchmarkGetPeerNetworkMap_AfterPeerAdded(b *testing.B) {
	account := createTestAccountWithEntities()
	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	var peerIDs []string
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		validatedPeersMap[peerID] = struct{}{}
		peerIDs = append(peerIDs, peerID)
	}
	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)
	newPeerID := "peer-new-101"
	newPeer := &nbpeer.Peer{
		ID:       newPeerID,
		IP:       net.IP{100, 64, 1, 1},
		Key:      fmt.Sprintf("key-%s", newPeerID),
		DNSLabel: "peernew101",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:   "user-admin",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
	}

	account.Peers[newPeerID] = newPeer
	account.Groups[devGroupID].Peers = append(account.Groups[devGroupID].Peers, newPeerID)
	account.Groups[allGroupID].Peers = append(account.Groups[allGroupID].Peers, newPeerID)
	validatedPeersMap[newPeerID] = struct{}{}

	b.ResetTimer()
	b.Run("old builder after add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, testingPeerID := range peerIDs {
				_ = account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil, nil, nil, account.GetActiveGroupUsers())
			}
		}
	})

	b.ResetTimer()
	b.Run("new builder after add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = builder.OnPeerAddedIncremental(account, newPeerID)
			for _, testingPeerID := range peerIDs {
				_ = builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)
			}
		}
	})
}

func TestGetPeerNetworkMap_Golden_WithNewRoutingPeer(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	newRouterID := "peer-new-router-102"
	newRouterIP := net.IP{100, 64, 1, 2}
	newRouter := &nbpeer.Peer{
		ID:        newRouterID,
		IP:        newRouterIP,
		Key:       fmt.Sprintf("key-%s", newRouterID),
		DNSLabel:  "newrouter102",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:    "user-admin",
		Meta:      nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
		LastLogin: func() *time.Time { t := time.Now(); return &t }(),
	}

	account.Peers[newRouterID] = newRouter

	if opsGroup, exists := account.Groups[opsGroupID]; exists {
		opsGroup.Peers = append(opsGroup.Peers, newRouterID)
	}

	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = append(allGroup.Peers, newRouterID)
	}

	newRoute := &route.Route{
		ID:                  route.ID("route-new-router"),
		Network:             netip.MustParsePrefix("172.16.0.0/24"),
		Peer:                newRouter.Key,
		PeerID:              newRouterID,
		Description:         "Route from new router",
		Enabled:             true,
		PeerGroups:          []string{opsGroupID},
		Groups:              []string{devGroupID, opsGroupID},
		AccessControlGroups: []string{devGroupID},
		AccountID:           account.Id,
	}
	account.Routes[newRoute.ID] = newRoute

	validatedPeersMap[newRouterID] = struct{}{}

	if account.Network != nil {
		account.Network.Serial++
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()

	networkMap := account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, nil, account.GetActiveGroupUsers())

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_with_new_router.json")

	t.Log("Update golden file with new router...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from OLD method with new router does not match golden file")
}

func TestGetPeerNetworkMap_Golden_New_WithOnPeerAddedRouter(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)

	newRouterID := "peer-new-router-102"
	newRouterIP := net.IP{100, 64, 1, 2}
	newRouter := &nbpeer.Peer{
		ID:        newRouterID,
		IP:        newRouterIP,
		Key:       fmt.Sprintf("key-%s", newRouterID),
		DNSLabel:  "newrouter102",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:    "user-admin",
		Meta:      nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
		LastLogin: func() *time.Time { t := time.Now(); return &t }(),
	}

	account.Peers[newRouterID] = newRouter

	if opsGroup, exists := account.Groups[opsGroupID]; exists {
		opsGroup.Peers = append(opsGroup.Peers, newRouterID)
	}
	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = append(allGroup.Peers, newRouterID)
	}

	newRoute := &route.Route{
		ID:                  route.ID("route-new-router"),
		Network:             netip.MustParsePrefix("172.16.0.0/24"),
		Peer:                newRouter.Key,
		PeerID:              newRouterID,
		Description:         "Route from new router",
		Enabled:             true,
		PeerGroups:          []string{opsGroupID},
		Groups:              []string{devGroupID, opsGroupID},
		AccessControlGroups: []string{devGroupID},
		AccountID:           account.Id,
	}
	account.Routes[newRoute.ID] = newRoute

	validatedPeersMap[newRouterID] = struct{}{}

	if account.Network != nil {
		account.Network.Serial++
	}

	err := builder.OnPeerAddedIncremental(account, newRouterID)
	require.NoError(t, err, "error adding router to cache")

	networkMap := builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_new_with_onpeeradded_router.json")

	t.Log("Update golden file with OnPeerAdded router...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from NEW builder with OnPeerAdded router does not match golden file")
}

func BenchmarkGetPeerNetworkMap_AfterRouterPeerAdded(b *testing.B) {
	account := createTestAccountWithEntities()
	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	var peerIDs []string
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		validatedPeersMap[peerID] = struct{}{}
		peerIDs = append(peerIDs, peerID)
	}
	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)
	newRouterID := "peer-new-router-102"
	newRouterIP := net.IP{100, 64, 1, 2}
	newRouter := &nbpeer.Peer{
		ID:        newRouterID,
		IP:        newRouterIP,
		Key:       fmt.Sprintf("key-%s", newRouterID),
		DNSLabel:  "newrouter102",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:    "user-admin",
		Meta:      nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
		LastLogin: func() *time.Time { t := time.Now(); return &t }(),
	}

	account.Peers[newRouterID] = newRouter

	if opsGroup, exists := account.Groups[opsGroupID]; exists {
		opsGroup.Peers = append(opsGroup.Peers, newRouterID)
	}
	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = append(allGroup.Peers, newRouterID)
	}

	newRoute := &route.Route{
		ID:                  route.ID("route-new-router"),
		Network:             netip.MustParsePrefix("172.16.0.0/24"),
		Peer:                newRouter.Key,
		PeerID:              newRouterID,
		Description:         "Route from new router",
		Enabled:             true,
		PeerGroups:          []string{opsGroupID},
		Groups:              []string{devGroupID, opsGroupID},
		AccessControlGroups: []string{devGroupID},
		AccountID:           account.Id,
	}
	account.Routes[newRoute.ID] = newRoute

	validatedPeersMap[newRouterID] = struct{}{}

	b.ResetTimer()
	b.Run("old builder after add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, testingPeerID := range peerIDs {
				_ = account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil, nil, nil, account.GetActiveGroupUsers())
			}
		}
	})

	b.ResetTimer()
	b.Run("new builder after add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = builder.OnPeerAddedIncremental(account, newRouterID)
			for _, testingPeerID := range peerIDs {
				_ = builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)
			}
		}
	})
}

func TestGetPeerNetworkMap_Golden_WithDeletedPeer(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	deletedPeerID := "peer-25" // peer from devs group

	delete(account.Peers, deletedPeerID)

	if devGroup, exists := account.Groups[devGroupID]; exists {
		devGroup.Peers = slices.DeleteFunc(devGroup.Peers, func(id string) bool {
			return id == deletedPeerID
		})
	}

	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = slices.DeleteFunc(allGroup.Peers, func(id string) bool {
			return id == deletedPeerID
		})
	}

	delete(validatedPeersMap, deletedPeerID)

	if account.Network != nil {
		account.Network.Serial++
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()

	networkMap := account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, nil, account.GetActiveGroupUsers())

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_with_deleted_peer.json")

	t.Log("Update golden file with deleted peer...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from OLD method with deleted peer does not match golden file")
}

func TestGetPeerNetworkMap_Golden_New_WithOnPeerDeleted(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)

	deletedPeerID := "peer-25" // devs group peer

	delete(account.Peers, deletedPeerID)

	if devGroup, exists := account.Groups[devGroupID]; exists {
		devGroup.Peers = slices.DeleteFunc(devGroup.Peers, func(id string) bool {
			return id == deletedPeerID
		})
	}

	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = slices.DeleteFunc(allGroup.Peers, func(id string) bool {
			return id == deletedPeerID
		})
	}

	delete(validatedPeersMap, deletedPeerID)

	if account.Network != nil {
		account.Network.Serial++
	}

	err := builder.OnPeerDeleted(account, deletedPeerID)
	require.NoError(t, err, "error deleting peer from cache")

	networkMap := builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_new_with_onpeerdeleted.json")
	t.Log("Update golden file with OnPeerDeleted...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from NEW builder with OnPeerDeleted does not match golden file")
}

func TestGetPeerNetworkMap_Golden_WithDeletedRouterPeer(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	deletedRouterID := "peer-75" // router peer

	var affectedRoute *route.Route
	for _, r := range account.Routes {
		if r.PeerID == deletedRouterID {
			affectedRoute = r
			break
		}
	}
	require.NotNil(t, affectedRoute, "Router peer should have a route")

	for _, group := range account.Groups {
		group.Peers = slices.DeleteFunc(group.Peers, func(id string) bool {
			return id == deletedRouterID
		})
	}

	for routeID, r := range account.Routes {
		if r.Peer == account.Peers[deletedRouterID].Key || r.PeerID == deletedRouterID {
			delete(account.Routes, routeID)
		}
	}
	delete(account.Peers, deletedRouterID)
	delete(validatedPeersMap, deletedRouterID)

	if account.Network != nil {
		account.Network.Serial++
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()

	networkMap := account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, resourcePolicies, routers, nil, account.GetActiveGroupUsers())

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_with_deleted_router_peer.json")

	t.Log("Update golden file with deleted peer...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from OLD method with deleted peer does not match golden file")
}

func TestGetPeerNetworkMap_Golden_New_WithDeletedRouterPeer(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)

	deletedRouterID := "peer-75" // router peer

	var affectedRoute *route.Route
	for _, r := range account.Routes {
		if r.PeerID == deletedRouterID {
			affectedRoute = r
			break
		}
	}
	require.NotNil(t, affectedRoute, "Router peer should have a route")

	for _, group := range account.Groups {
		group.Peers = slices.DeleteFunc(group.Peers, func(id string) bool {
			return id == deletedRouterID
		})
	}
	for routeID, r := range account.Routes {
		if r.Peer == account.Peers[deletedRouterID].Key || r.PeerID == deletedRouterID {
			delete(account.Routes, routeID)
		}
	}
	delete(account.Peers, deletedRouterID)
	delete(validatedPeersMap, deletedRouterID)

	if account.Network != nil {
		account.Network.Serial++
	}

	err := builder.OnPeerDeleted(account, deletedRouterID)
	require.NoError(t, err, "error deleting routing peer from cache")

	networkMap := builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err)

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_new_with_deleted_router.json")

	t.Log("Update golden file with deleted router...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err)

	require.JSONEq(t, string(expectedJSON), string(jsonData),
		"network map after deleting router does not match golden file")
}

func BenchmarkGetPeerNetworkMap_AfterPeerDeleted(b *testing.B) {
	account := createTestAccountWithEntities()
	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	var peerIDs []string
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		validatedPeersMap[peerID] = struct{}{}
		peerIDs = append(peerIDs, peerID)
	}

	deletedPeerID := "peer-25"

	delete(account.Peers, deletedPeerID)
	account.Groups[devGroupID].Peers = slices.DeleteFunc(account.Groups[devGroupID].Peers, func(id string) bool {
		return id == deletedPeerID
	})
	account.Groups[allGroupID].Peers = slices.DeleteFunc(account.Groups[allGroupID].Peers, func(id string) bool {
		return id == deletedPeerID
	})
	delete(validatedPeersMap, deletedPeerID)

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)

	b.ResetTimer()
	b.Run("old builder after delete", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, testingPeerID := range peerIDs {
				_ = account.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil, nil, nil, account.GetActiveGroupUsers())
			}
		}
	})

	b.ResetTimer()
	b.Run("new builder after delete", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = builder.OnPeerDeleted(account, deletedPeerID)
			for _, testingPeerID := range peerIDs {
				_ = builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)
			}
		}
	})
}

func normalizeAndSortNetworkMap(networkMap *types.NetworkMap) {
	for _, peer := range networkMap.Peers {
		if peer.Status != nil {
			peer.Status.LastSeen = time.Time{}
		}
		peer.LastLogin = &time.Time{}
	}
	for _, peer := range networkMap.OfflinePeers {
		if peer.Status != nil {
			peer.Status.LastSeen = time.Time{}
		}
		peer.LastLogin = &time.Time{}
	}

	sort.Slice(networkMap.Peers, func(i, j int) bool { return networkMap.Peers[i].ID < networkMap.Peers[j].ID })
	sort.Slice(networkMap.OfflinePeers, func(i, j int) bool { return networkMap.OfflinePeers[i].ID < networkMap.OfflinePeers[j].ID })
	sort.Slice(networkMap.Routes, func(i, j int) bool { return networkMap.Routes[i].ID < networkMap.Routes[j].ID })

	sort.Slice(networkMap.FirewallRules, func(i, j int) bool {
		r1, r2 := networkMap.FirewallRules[i], networkMap.FirewallRules[j]
		if r1.PeerIP != r2.PeerIP {
			return r1.PeerIP < r2.PeerIP
		}
		if r1.Protocol != r2.Protocol {
			return r1.Protocol < r2.Protocol
		}
		if r1.Direction != r2.Direction {
			return r1.Direction < r2.Direction
		}
		if r1.Action != r2.Action {
			return r1.Action < r2.Action
		}
		return r1.Port < r2.Port
	})

	sort.Slice(networkMap.RoutesFirewallRules, func(i, j int) bool {
		r1, r2 := networkMap.RoutesFirewallRules[i], networkMap.RoutesFirewallRules[j]
		if r1.RouteID != r2.RouteID {
			return r1.RouteID < r2.RouteID
		}
		if r1.Action != r2.Action {
			return r1.Action < r2.Action
		}
		if r1.Destination != r2.Destination {
			return r1.Destination < r2.Destination
		}
		if len(r1.SourceRanges) > 0 && len(r2.SourceRanges) > 0 {
			if r1.SourceRanges[0] != r2.SourceRanges[0] {
				return r1.SourceRanges[0] < r2.SourceRanges[0]
			}
		}
		return r1.Port < r2.Port
	})

	for _, ranges := range networkMap.RoutesFirewallRules {
		sort.Slice(ranges.SourceRanges, func(i, j int) bool {
			return ranges.SourceRanges[i] < ranges.SourceRanges[j]
		})
	}
}

func createTestAccountWithEntities() *types.Account {
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

	groups := map[string]*types.Group{
		allGroupID: {ID: allGroupID, Name: "All", Peers: allGroupPeers},
		devGroupID: {ID: devGroupID, Name: "Developers", Peers: devGroupPeers},
		opsGroupID: {ID: opsGroupID, Name: "Operations", Peers: opsGroupPeers},
	}

	policies := []*types.Policy{
		{
			ID: policyIDAll, Name: "Default-Allow", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: policyIDAll, Name: "Allow All", Enabled: true, Action: types.PolicyTrafficActionAccept,
				Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
				Sources: []string{allGroupID}, Destinations: []string{allGroupID},
			}},
		},
		{
			ID: policyIDDevOps, Name: "Dev to Ops Web Access", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: policyIDDevOps, Name: "Dev -> Ops (HTTP Range)", Enabled: true, Action: types.PolicyTrafficActionAccept,
				Protocol: types.PolicyRuleProtocolTCP, Bidirectional: false,
				PortRanges: []types.RulePortRange{{Start: 8080, End: 8090}},
				Sources:    []string{devGroupID}, Destinations: []string{opsGroupID},
			}},
		},
		{
			ID: policyIDDrop, Name: "Drop DB traffic", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: policyIDDrop, Name: "Drop DB", Enabled: true, Action: types.PolicyTrafficActionDrop,
				Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"5432"}, Bidirectional: true,
				Sources: []string{devGroupID}, Destinations: []string{opsGroupID},
			}},
		},
		{
			ID: policyIDPosture, Name: "Posture Check for DB Resource", Enabled: true,
			SourcePostureChecks: []string{postureCheckID},
			Rules: []*types.PolicyRule{{
				ID: policyIDPosture, Name: "Allow DB Access", Enabled: true, Action: types.PolicyTrafficActionAccept,
				Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
				Sources: []string{opsGroupID}, DestinationResource: types.Resource{ID: networkResourceID},
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

	account := &types.Account{
		Id: testAccountID, Peers: peers, Groups: groups, Policies: policies, Routes: routes,
		Network: &types.Network{
			Identifier: "net-golden-test", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(16, 32)}, Serial: 1,
		},
		DNSSettings: types.DNSSettings{DisabledManagementGroups: []string{opsGroupID}},
		NameServerGroups: map[string]*dns.NameServerGroup{
			nameserverGroupID: {
				ID: nameserverGroupID, Name: "Main NS", Enabled: true, Groups: []string{devGroupID},
				NameServers: []dns.NameServer{{IP: netip.MustParseAddr("8.8.8.8"), NSType: dns.UDPNameServerType, Port: 53}},
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
		Settings: &types.Settings{PeerLoginExpirationEnabled: true, PeerLoginExpiration: 1 * time.Hour},
	}

	for _, p := range account.Policies {
		p.AccountID = account.Id
	}
	for _, r := range account.Routes {
		r.AccountID = account.Id
	}

	return account
}

func TestGetPeerNetworkMap_Golden_New_WithOnPeerAddedRouter_Batched(t *testing.T) {
	account := createTestAccountWithEntities()

	ctx := context.Background()
	validatedPeersMap := make(map[string]struct{})
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if peerID == offlinePeerID {
			continue
		}
		validatedPeersMap[peerID] = struct{}{}
	}

	builder := types.NewNetworkMapBuilder(account, validatedPeersMap)

	newRouterID := "peer-new-router-102"
	newRouterIP := net.IP{100, 64, 1, 2}
	newRouter := &nbpeer.Peer{
		ID:        newRouterID,
		IP:        newRouterIP,
		Key:       fmt.Sprintf("key-%s", newRouterID),
		DNSLabel:  "newrouter102",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		UserID:    "user-admin",
		Meta:      nbpeer.PeerSystemMeta{WtVersion: "0.26.0", GoOS: "linux"},
		LastLogin: func() *time.Time { t := time.Now(); return &t }(),
	}

	account.Peers[newRouterID] = newRouter

	if opsGroup, exists := account.Groups[opsGroupID]; exists {
		opsGroup.Peers = append(opsGroup.Peers, newRouterID)
	}
	if allGroup, exists := account.Groups[allGroupID]; exists {
		allGroup.Peers = append(allGroup.Peers, newRouterID)
	}

	newRoute := &route.Route{
		ID:                  route.ID("route-new-router"),
		Network:             netip.MustParsePrefix("172.16.0.0/24"),
		Peer:                newRouter.Key,
		PeerID:              newRouterID,
		Description:         "Route from new router",
		Enabled:             true,
		PeerGroups:          []string{opsGroupID},
		Groups:              []string{devGroupID, opsGroupID},
		AccessControlGroups: []string{devGroupID},
		AccountID:           account.Id,
	}
	account.Routes[newRoute.ID] = newRoute

	validatedPeersMap[newRouterID] = struct{}{}

	if account.Network != nil {
		account.Network.Serial++
	}

	builder.EnqueuePeersForIncrementalAdd(account, newRouterID)

	time.Sleep(100 * time.Millisecond)

	networkMap := builder.GetPeerNetworkMap(ctx, testingPeerID, dns.CustomZone{}, validatedPeersMap, nil)

	normalizeAndSortNetworkMap(networkMap)

	jsonData, err := json.MarshalIndent(networkMap, "", "  ")
	require.NoError(t, err, "error marshaling network map to JSON")

	goldenFilePath := filepath.Join("testdata", "networkmap_golden_new_with_onpeeradded_router.json")

	t.Log("Update golden file with OnPeerAdded router...")
	err = os.MkdirAll(filepath.Dir(goldenFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(goldenFilePath, jsonData, 0644)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err, "error reading golden file")

	require.JSONEq(t, string(expectedJSON), string(jsonData), "network map from NEW builder with OnPeerAdded router does not match golden file")
}
