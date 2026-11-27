package exitnodes_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// The scenario: laptops reach the internet through exit node "office-exit", routed by
// exit-a and exit-b. exit-c belongs to the exit node but is disabled. other is in no
// group the policy names. The policy targets the exit node, not its peers.
const (
	testDNSDomain = "netbird.test"
	exitNodeID    = "en-1"
	exitNodeName  = "office-exit"
	laptopsGroup  = "laptops"
	othersGroup   = "others"
	exitPolicyID  = "policy-exit"
)

var testPeerIPs = map[string]string{
	"laptop": "100.64.0.1",
	"other":  "100.64.0.2",
	"exit-a": "100.64.0.10",
	"exit-b": "100.64.0.11",
	"exit-c": "100.64.0.12",
}

func testExitNode() *exitnodes.ExitNode {
	node := &exitnodes.ExitNode{
		ID:        exitNodeID,
		AccountID: "acc",
		PublicID:  "en-1-public",
		Name:      exitNodeName,
		Enabled:   true,
		AutoApply: true,
		Peers: []exitnodes.Peer{
			{PeerID: "exit-a", PublicID: "exit-a-public", Metric: 10, Enabled: true},
			{PeerID: "exit-b", PublicID: "exit-b-public", Metric: 20, Enabled: true},
			{PeerID: "exit-c", PublicID: "exit-c-public", Metric: 30, Enabled: false},
		},
	}
	node.BindPeers()
	return node
}

func peerKey(peerID string) string {
	sum := sha256.Sum256([]byte(peerID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func overlayNet() net.IPNet {
	_, ipnet, _ := net.ParseCIDR("100.64.0.0/10")
	return *ipnet
}

func groupMembers() map[string][]string {
	return map[string][]string{
		laptopsGroup: {"laptop"},
		othersGroup:  {"other"},
	}
}

func testNetworkMapData() *networkmap.NetworkMapData {
	nmd := &networkmap.NetworkMapData{
		Peers:           make(map[string]*nmdata.Peer),
		Groups:          make(map[string]*nmdata.Group),
		Network:         &nmdata.Network{Identifier: "network", Net: overlayNet()},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		ValidatedPeers:  make(map[string]struct{}),
		Policies: []*nmdata.Policy{{
			ID:       exitPolicyID,
			PublicID: exitPolicyID,
			Enabled:  true,
			Rules: []*nmdata.PolicyRule{{
				ID:                  exitPolicyID,
				PolicyID:            exitPolicyID,
				Enabled:             true,
				Action:              string(types.PolicyTrafficActionAccept),
				Protocol:            string(types.PolicyRuleProtocolALL),
				Sources:             []string{laptopsGroup},
				DestinationResource: nmdata.Resource{ID: exitNodeID, Type: exitnodes.PolicyResourceType},
			}},
		}},
	}
	for id, ip := range testPeerIPs {
		nmd.Peers[id] = &nmdata.Peer{ID: id, Key: peerKey(id), DNSLabel: id, IP: netip.MustParseAddr(ip)}
		nmd.ValidatedPeers[id] = struct{}{}
	}
	for id, members := range groupMembers() {
		nmd.Groups[id] = &nmdata.Group{ID: id, PublicID: id, Name: id, Peers: members}
	}
	return nmd
}

func testAccount() *types.Account {
	account := &types.Account{
		Id:       "acc",
		Network:  &types.Network{Identifier: "network", Net: overlayNet()},
		Settings: &types.Settings{},
		Peers:    make(map[string]*nbpeer.Peer),
		Groups:   make(map[string]*types.Group),
		Users:    make(map[string]*types.User),
		Policies: []*types.Policy{{
			ID:        exitPolicyID,
			PublicID:  exitPolicyID,
			AccountID: "acc",
			Enabled:   true,
			Rules: []*types.PolicyRule{{
				ID:                  exitPolicyID,
				PolicyID:            exitPolicyID,
				Enabled:             true,
				Action:              types.PolicyTrafficActionAccept,
				Protocol:            types.PolicyRuleProtocolALL,
				Sources:             []string{laptopsGroup},
				DestinationResource: types.Resource{ID: exitNodeID, Type: exitnodes.PolicyResourceType},
			}},
		}},
	}
	for id, ip := range testPeerIPs {
		account.Peers[id] = &nbpeer.Peer{
			ID: id, AccountID: "acc", Key: peerKey(id), DNSLabel: id, IP: netip.MustParseAddr(ip),
			Status: &nbpeer.PeerStatus{Connected: true},
		}
	}
	for id, members := range groupMembers() {
		account.Groups[id] = &types.Group{ID: id, PublicID: id, AccountID: "acc", Name: id, Peers: members}
	}
	return account
}

// networkMapsFor returns the peer's network map as each server path and client builds it:
// the network map data the store loads, sent as components to new clients or computed on
// the server for old ones, and the account fallback path.
func networkMapsFor(t *testing.T, peerID string) map[string]*proto.NetworkMap {
	t.Helper()
	return networkMapsForNode(t, peerID, testExitNode())
}

func networkMapsForNode(t *testing.T, peerID string, node *exitnodes.ExitNode) map[string]*proto.NetworkMap {
	t.Helper()
	ctx := context.Background()
	nodes := []*exitnodes.ExitNode{node}

	nmd := testNetworkMapData()
	exitnodes.InjectIntoNetworkMapData(nmd, nodes)
	peer := nmd.Peers[peerID]

	components := nmd.GetPeerNetworkMapComponents(peerID, nmdata.CustomZone{})
	resp := mgmtgrpc.ToComponentSyncResponse(ctx, nil, nil, nil, peer, nil, nil, components,
		testDNSDomain, nil, nmd.AccountSettings, nil, maps.Keys(nmd.GetPeerGroups(peerID)), 0)
	envelope, err := networkmap.EnvelopeToNetworkMap(ctx, resp.NetworkMapEnvelope, peer.Key, testDNSDomain, false)
	require.NoError(t, err, "the client should decode the envelope")

	fromData := controller.NetworkMapFromData(ctx, nmd, peerID, nmdata.CustomZone{}, nil)

	account := testAccount()
	exitnodes.InjectIntoAccount(account, nodes)
	validated := make(map[string]struct{}, len(account.Peers))
	for id := range account.Peers {
		validated[id] = struct{}{}
	}
	fromAccount := account.GetPeerNetworkMapFromComponents(ctx, peerID, nbdns.CustomZone{}, nil, validated,
		account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), nil, account.GetActiveGroupUsers())

	toProto := func(nm *types.NetworkMap) *proto.NetworkMap {
		return mgmtgrpc.ToSyncResponse(ctx, nil, nil, nil, peer, nil, nil, nm, testDNSDomain, nil,
			&cache.DNSConfigCache{}, nmd.AccountSettings, nil, nil, 0).NetworkMap
	}

	return map[string]*proto.NetworkMap{
		"components client": envelope.NetworkMap,
		"store path":        toProto(fromData),
		"account path":      toProto(fromAccount),
	}
}

func exitRoutes(nm *proto.NetworkMap) map[string]*proto.Route {
	routes := make(map[string]*proto.Route)
	for _, r := range nm.GetRoutes() {
		if r.GetNetwork() == "0.0.0.0/0" {
			routes[r.GetPeer()] = r
		}
	}
	return routes
}

func remotePeerKeys(nm *proto.NetworkMap) map[string]bool {
	keys := make(map[string]bool)
	for _, p := range nm.GetRemotePeers() {
		keys[p.GetWgPubKey()] = true
	}
	return keys
}

func TestExitNodeNetworkMap_SourcePeer(t *testing.T) {
	for path, nm := range networkMapsFor(t, "laptop") {
		t.Run(path, func(t *testing.T) {
			routes := exitRoutes(nm)
			require.Len(t, routes, 2, "the laptop should get one exit route per enabled exit node peer")

			for peerID, metric := range map[string]int64{"exit-a": 10, "exit-b": 20} {
				r := routes[peerKey(peerID)]
				require.NotNil(t, r, "the laptop should route through %s", peerID)
				assert.Equal(t, exitNodeName, r.GetNetID(), "the exit route should carry the exit node name")
				assert.Equal(t, metric, r.GetMetric(), "the exit route should carry the peer metric")
				assert.True(t, r.GetMasquerade(), "exit traffic should be masqueraded")
				assert.False(t, r.GetSkipAutoApply(), "an auto applied exit node should be selected on the client")
			}
			assert.NotContains(t, routes, peerKey("exit-c"), "a disabled exit node peer should not route")

			peers := remotePeerKeys(nm)
			assert.True(t, peers[peerKey("exit-a")], "the laptop should connect to exit-a")
			assert.True(t, peers[peerKey("exit-b")], "the laptop should connect to exit-b")
			assert.False(t, peers[peerKey("exit-c")], "the laptop should not connect to a disabled exit node peer")
			assert.Empty(t, nm.GetFirewallRules(), "the exit node policy should not open the exit node peers themselves")
		})
	}
}

func TestExitNodeNetworkMap_AutoApplyOff(t *testing.T) {
	node := testExitNode()
	node.AutoApply = false

	for path, nm := range networkMapsForNode(t, "laptop", node) {
		t.Run(path, func(t *testing.T) {
			routes := exitRoutes(nm)
			require.Len(t, routes, 2, "the laptop should still get the exit routes to select them")

			for _, r := range routes {
				assert.True(t, r.GetSkipAutoApply(), "the exit route should not be applied automatically")
			}
		})
	}
}

func TestExitNodeNetworkMap_PeerOutsidePolicy(t *testing.T) {
	for path, nm := range networkMapsFor(t, "other") {
		t.Run(path, func(t *testing.T) {
			assert.Empty(t, exitRoutes(nm), "a peer outside the policy sources should get no exit route")
			assert.Empty(t, nm.GetRemotePeers(), "a peer outside the policy sources should connect to no exit node peer")
		})
	}
}

func TestExitNodeNetworkMap_RoutingPeer(t *testing.T) {
	for path, nm := range networkMapsFor(t, "exit-a") {
		t.Run(path, func(t *testing.T) {
			assert.True(t, remotePeerKeys(nm)[peerKey("laptop")], "the routing peer should connect to the laptop")
			assert.False(t, remotePeerKeys(nm)[peerKey("other")], "the routing peer should not connect to peers outside the policy")

			var sources []string
			for _, rule := range nm.GetRoutesFirewallRules() {
				if rule.GetDestination() == "0.0.0.0/0" {
					sources = append(sources, rule.GetSourceRanges()...)
				}
			}
			assert.Equal(t, []string{"100.64.0.1/32"}, sources, "the routing peer should forward internet traffic of the laptop only")
		})
	}
}

func TestExitNodeNetworkMap_DisabledExitNode(t *testing.T) {
	ctx := context.Background()
	node := testExitNode()
	node.Enabled = false

	nmd := testNetworkMapData()
	exitnodes.InjectIntoNetworkMapData(nmd, []*exitnodes.ExitNode{node})
	assert.Empty(t, nmd.NetworkResources, "a disabled exit node should not be sent")

	account := testAccount()
	exitnodes.InjectIntoAccount(account, []*exitnodes.ExitNode{node})
	assert.Empty(t, account.NetworkResources, "a disabled exit node should not be added to the account")

	nm := controller.NetworkMapFromData(ctx, nmd, "laptop", nmdata.CustomZone{}, nil)
	assert.Empty(t, nm.Routes, "the laptop should get no route from a disabled exit node")
}

func TestInjectIntoAccount_DoesNotWriteSharedSlices(t *testing.T) {
	account := testAccount()
	account.NetworkResources = make([]*resourceTypes.NetworkResource, 0, 4)
	shared := account.NetworkResources[:cap(account.NetworkResources)]

	// A shallow copy, as the account request buffer hands out, shares the slices.
	copied := *account
	exitnodes.InjectIntoAccount(&copied, []*exitnodes.ExitNode{testExitNode()})

	require.Len(t, copied.NetworkResources, 1)
	assert.Nil(t, shared[0], "injecting into a copy must not write into the original's backing array")
	assert.Empty(t, account.NetworkResources, "the original account should keep its resources")
}
