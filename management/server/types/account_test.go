package types

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/route"
)

func setupTestAccount() *Account {
	return &Account{
		Id: "accountID",
		Peers: map[string]*nbpeer.Peer{
			"peer1": {
				ID:        "peer1",
				AccountID: "accountID",
				Key:       "peer1Key",
			},
			"peer2": {
				ID:        "peer2",
				AccountID: "accountID",
				Key:       "peer2Key",
			},
			"peer3": {
				ID:        "peer3",
				AccountID: "accountID",
				Key:       "peer3Key",
			},
			"peer11": {
				ID:        "peer11",
				AccountID: "accountID",
				Key:       "peer11Key",
			},
			"peer12": {
				ID:        "peer12",
				AccountID: "accountID",
				Key:       "peer12Key",
			},
			"peer21": {
				ID:        "peer21",
				AccountID: "accountID",
				Key:       "peer21Key",
			},
			"peer31": {
				ID:        "peer31",
				AccountID: "accountID",
				Key:       "peer31Key",
			},
			"peer32": {
				ID:        "peer32",
				AccountID: "accountID",
				Key:       "peer32Key",
			},
			"peer41": {
				ID:        "peer41",
				AccountID: "accountID",
				Key:       "peer41Key",
			},
			"peer51": {
				ID:        "peer51",
				AccountID: "accountID",
				Key:       "peer51Key",
			},
			"peer61": {
				ID:        "peer61",
				AccountID: "accountID",
				Key:       "peer61Key",
			},
		},
		Groups: map[string]*Group{
			"group1": {
				ID:    "group1",
				Peers: []string{"peer11", "peer12"},
				Resources: []Resource{
					{
						ID:   "resource1ID",
						Type: "Host",
					},
				},
			},
			"group2": {
				ID:    "group2",
				Peers: []string{"peer21"},
				Resources: []Resource{
					{
						ID:   "resource2ID",
						Type: "Domain",
					},
				},
			},
			"group3": {
				ID:    "group3",
				Peers: []string{"peer31", "peer32"},
				Resources: []Resource{
					{
						ID:   "resource3ID",
						Type: "Subnet",
					},
				},
			},
			"group4": {
				ID:    "group4",
				Peers: []string{"peer41"},
				Resources: []Resource{
					{
						ID:   "resource3ID",
						Type: "Subnet",
					},
				},
			},
			"group5": {
				ID:    "group5",
				Peers: []string{"peer51"},
			},
			"group6": {
				ID:    "group6",
				Peers: []string{"peer61"},
			},
		},
		Networks: []*networkTypes.Network{
			{
				ID:        "network1ID",
				AccountID: "accountID",
				Name:      "network1",
			},
			{
				ID:        "network2ID",
				AccountID: "accountID",
				Name:      "network2",
			},
			{
				ID:        "network3ID",
				AccountID: "accountID",
				Name:      "network3",
			},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{
				ID:         "router1ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "peer1",
				PeerGroups: []string{},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
			{
				ID:         "router2ID",
				NetworkID:  "network2ID",
				AccountID:  "accountID",
				Peer:       "peer2",
				PeerGroups: []string{},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
			{
				ID:         "router3ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "peer3",
				PeerGroups: []string{},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
			{
				ID:         "router4ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group1"},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
			{
				ID:         "router5ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group2", "group3"},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
			{
				ID:         "router6ID",
				NetworkID:  "network2ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group4"},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
			{
				ID:         "router6ID",
				NetworkID:  "network3ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group6"},
				Masquerade: false,
				Metric:     100,
				Enabled:    false,
			},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID:        "resource1ID",
				AccountID: "accountID",
				NetworkID: "network1ID",
				Enabled:   true,
			},
			{
				ID:        "resource2ID",
				AccountID: "accountID",
				NetworkID: "network2ID",
				Enabled:   true,
			},
			{
				ID:        "resource3ID",
				AccountID: "accountID",
				NetworkID: "network1ID",
				Enabled:   true,
			},
			{
				ID:        "resource4ID",
				AccountID: "accountID",
				NetworkID: "network1ID",
				Enabled:   true,
			},
			{
				ID:        "resource5ID",
				AccountID: "accountID",
				NetworkID: "network3ID",
				Enabled:   false,
			},
		},
		Policies: []*Policy{
			{
				ID:        "policy1ID",
				AccountID: "accountID",
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:           "rule1ID",
						Enabled:      true,
						Destinations: []string{"group1"},
					},
				},
			},
			{
				ID:        "policy2ID",
				AccountID: "accountID",
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:           "rule2ID",
						Enabled:      true,
						Destinations: []string{"group3"},
					},
				},
			},
			{
				ID:        "policy3ID",
				AccountID: "accountID",
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:           "rule3ID",
						Enabled:      true,
						Destinations: []string{"group2", "group4"},
					},
				},
			},
			{
				ID:        "policy4ID",
				AccountID: "accountID",
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:      "rule4ID",
						Enabled: true,
						DestinationResource: Resource{
							ID:   "resource4ID",
							Type: "Host",
						},
					},
				},
			},
			{
				ID:        "policy5ID",
				AccountID: "accountID",
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:      "rule5ID",
						Enabled: true,
					},
				},
			},
			{
				ID:        "policy6ID",
				AccountID: "accountID",
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:      "rule6ID",
						Enabled: true,
					},
				},
			},
		},
	}
}

func Test_GetResourceRoutersMap(t *testing.T) {
	account := setupTestAccount()
	routers := account.GetResourceRoutersMap()
	require.Equal(t, 2, len(routers))

	require.Equal(t, 7, len(routers["network1ID"]))
	require.NotNil(t, routers["network1ID"]["peer1"])
	require.NotNil(t, routers["network1ID"]["peer3"])
	require.NotNil(t, routers["network1ID"]["peer11"])
	require.NotNil(t, routers["network1ID"]["peer12"])
	require.NotNil(t, routers["network1ID"]["peer21"])
	require.NotNil(t, routers["network1ID"]["peer31"])
	require.NotNil(t, routers["network1ID"]["peer32"])

	require.Equal(t, 2, len(routers["network2ID"]))
	require.NotNil(t, routers["network2ID"]["peer2"])
	require.NotNil(t, routers["network2ID"]["peer41"])

	require.Equal(t, 0, len(routers["network3ID"]))
}

func Test_GetResourcePoliciesMap(t *testing.T) {
	account := setupTestAccount()
	policies := account.GetResourcePoliciesMap()
	require.Equal(t, 4, len(policies))
	require.Equal(t, 1, len(policies["resource1ID"]))
	require.Equal(t, 1, len(policies["resource2ID"]))
	require.Equal(t, 2, len(policies["resource3ID"]))
	require.Equal(t, 1, len(policies["resource4ID"]))
	require.Equal(t, 0, len(policies["resource5ID"]))
}

func Test_AddNetworksRoutingPeersAddsMissingPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1Key", ID: "peer1"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer2Key", PeerID: "peer2"},
		{Peer: "peer3Key", PeerID: "peer3"},
	}
	peersToConnect := []*nbpeer.Peer{
		{Key: "peer2Key", ID: "peer2"},
	}
	expiredPeers := []*nbpeer.Peer{
		{Key: "peer4Key", ID: "peer4"},
	}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, map[string]struct{}{})
	require.Len(t, result, 2)
	require.Equal(t, "peer2Key", result[0].Key)
	require.Equal(t, "peer3Key", result[1].Key)
}

func Test_AddNetworksRoutingPeersIgnoresExistingPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1Key", ID: "peer1"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer2Key"},
	}
	peersToConnect := []*nbpeer.Peer{
		{Key: "peer2Key", ID: "peer2"},
	}
	expiredPeers := []*nbpeer.Peer{}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, map[string]struct{}{})
	require.Len(t, result, 1)
	require.Equal(t, "peer2Key", result[0].Key)
}

func Test_AddNetworksRoutingPeersAddsExpiredPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1Key", ID: "peer1"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer2Key", PeerID: "peer2"},
		{Peer: "peer3Key", PeerID: "peer3"},
	}
	peersToConnect := []*nbpeer.Peer{
		{Key: "peer2Key", ID: "peer2"},
	}
	expiredPeers := []*nbpeer.Peer{
		{Key: "peer3Key", ID: "peer3"},
	}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, map[string]struct{}{})
	require.Len(t, result, 1)
	require.Equal(t, "peer2Key", result[0].Key)
}

func Test_AddNetworksRoutingPeersExcludesSelf(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1Key", ID: "peer1"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer1Key", PeerID: "peer1"},
		{Peer: "peer2Key", PeerID: "peer2"},
	}
	peersToConnect := []*nbpeer.Peer{}
	expiredPeers := []*nbpeer.Peer{}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, true, map[string]struct{}{})
	require.Len(t, result, 1)
	require.Equal(t, "peer2Key", result[0].Key)
}

func Test_AddNetworksRoutingPeersHandlesNoMissingPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1key", ID: "peer1"}
	networkResourcesRoutes := []*route.Route{}
	peersToConnect := []*nbpeer.Peer{}
	expiredPeers := []*nbpeer.Peer{}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, map[string]struct{}{})
	require.Len(t, result, 0)
}

const (
	accID                                = "accountID"
	network1ID                           = "network1ID"
	group1ID                             = "group1"
	accNetResourcePeer1ID                = "peer1"
	accNetResourcePeer2ID                = "peer2"
	accNetResourceRouter1ID              = "router1"
	accNetResource1ID                    = "resource1ID"
	accNetResourceRestrictPostureCheckID = "restrictPostureCheck"
	accNetResourceRelaxedPostureCheckID  = "relaxedPostureCheck"
	accNetResourceLockedPostureCheckID   = "lockedPostureCheck"
	accNetResourceLinuxPostureCheckID    = "linuxPostureCheck"
)

var (
	accNetResourcePeer1IP    = net.IP{192, 168, 1, 1}
	accNetResourcePeer2IP    = net.IP{192, 168, 1, 2}
	accNetResourceRouter1IP  = net.IP{192, 168, 1, 3}
	accNetResourceValidPeers = map[string]struct{}{accNetResourcePeer1ID: {}, accNetResourcePeer2ID: {}}
)

func getBasicAccountsWithResource() *Account {
	return &Account{
		Id: accID,
		Peers: map[string]*nbpeer.Peer{
			accNetResourcePeer1ID: {
				ID:        accNetResourcePeer1ID,
				AccountID: accID,
				Key:       "peer1Key",
				IP:        accNetResourcePeer1IP,
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					WtVersion:     "0.35.1",
					KernelVersion: "4.4.0",
				},
			},
			accNetResourcePeer2ID: {
				ID:        accNetResourcePeer2ID,
				AccountID: accID,
				Key:       "peer2Key",
				IP:        accNetResourcePeer2IP,
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "windows",
					WtVersion:     "0.34.1",
					KernelVersion: "4.4.0",
				},
			},
			accNetResourceRouter1ID: {
				ID:        accNetResourceRouter1ID,
				AccountID: accID,
				Key:       "router1Key",
				IP:        accNetResourceRouter1IP,
				Meta: nbpeer.PeerSystemMeta{
					GoOS:          "linux",
					WtVersion:     "0.35.1",
					KernelVersion: "4.4.0",
				},
			},
		},
		Groups: map[string]*Group{
			group1ID: {
				ID:    group1ID,
				Peers: []string{accNetResourcePeer1ID, accNetResourcePeer2ID},
			},
		},
		Networks: []*networkTypes.Network{
			{
				ID:        network1ID,
				AccountID: accID,
				Name:      "network1",
			},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{
				ID:         accNetResourceRouter1ID,
				NetworkID:  network1ID,
				AccountID:  accID,
				Peer:       accNetResourceRouter1ID,
				PeerGroups: []string{},
				Masquerade: false,
				Metric:     100,
				Enabled:    true,
			},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID:        accNetResource1ID,
				AccountID: accID,
				NetworkID: network1ID,
				Address:   "10.10.10.0/24",
				Prefix:    netip.MustParsePrefix("10.10.10.0/24"),
				Type:      resourceTypes.NetworkResourceType("subnet"),
				Enabled:   true,
			},
		},
		Policies: []*Policy{
			{
				ID:        "policy1ID",
				AccountID: accID,
				Enabled:   true,
				Rules: []*PolicyRule{
					{
						ID:      "rule1ID",
						Enabled: true,
						Sources: []string{group1ID},
						DestinationResource: Resource{
							ID:   accNetResource1ID,
							Type: "Host",
						},
						Protocol: PolicyRuleProtocolTCP,
						Ports:    []string{"80"},
						Action:   PolicyTrafficActionAccept,
					},
				},
				SourcePostureChecks: nil,
			},
		},
		PostureChecks: []*posture.Checks{
			{
				ID:   accNetResourceRestrictPostureCheckID,
				Name: accNetResourceRestrictPostureCheckID,
				Checks: posture.ChecksDefinition{
					NBVersionCheck: &posture.NBVersionCheck{
						MinVersion: "0.35.0",
					},
				},
			},
			{
				ID:   accNetResourceRelaxedPostureCheckID,
				Name: accNetResourceRelaxedPostureCheckID,
				Checks: posture.ChecksDefinition{
					NBVersionCheck: &posture.NBVersionCheck{
						MinVersion: "0.0.1",
					},
				},
			},
			{
				ID:   accNetResourceLockedPostureCheckID,
				Name: accNetResourceLockedPostureCheckID,
				Checks: posture.ChecksDefinition{
					NBVersionCheck: &posture.NBVersionCheck{
						MinVersion: "7.7.7",
					},
				},
			},
			{
				ID:   accNetResourceLinuxPostureCheckID,
				Name: accNetResourceLinuxPostureCheckID,
				Checks: posture.ChecksDefinition{
					OSVersionCheck: &posture.OSVersionCheck{
						Linux: &posture.MinKernelVersionCheck{
							MinKernelVersion: "0.0.0"},
					},
				},
			},
		},
	}
}

func Test_NetworksNetMapGenWithNoPostureChecks(t *testing.T) {
	account := getBasicAccountsWithResource()

	// all peers should match the policy

	// validate for peer1
	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate for peer2
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer2ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate routes for router1
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourceRouter1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.True(t, isRouter, "should be router")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 2, "expected source peers don't match")
	assert.NotNil(t, sourcePeers[accNetResourcePeer1ID], "expected source peers don't match")
	assert.NotNil(t, sourcePeers[accNetResourcePeer2ID], "expected source peers don't match")

	// validate rules for router1
	rules := account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers[accNetResourceRouter1ID], accNetResourceValidPeers, networkResourcesRoutes, account.GetResourcePoliciesMap())
	assert.Len(t, rules, 1, "expected rules count don't match")
	assert.Equal(t, uint16(80), rules[0].Port, "should have port 80")
	assert.Equal(t, "tcp", rules[0].Protocol, "should have protocol tcp")
	if !slices.Contains(rules[0].SourceRanges, accNetResourcePeer1IP.String()+"/32") {
		t.Errorf("%s should have source range of peer1 %s", rules[0].SourceRanges, accNetResourcePeer1IP.String())
	}
	if !slices.Contains(rules[0].SourceRanges, accNetResourcePeer2IP.String()+"/32") {
		t.Errorf("%s should have source range of peer2 %s", rules[0].SourceRanges, accNetResourcePeer2IP.String())
	}
}

func Test_NetworksNetMapGenWithPostureChecks(t *testing.T) {
	account := getBasicAccountsWithResource()

	// should allow peer1 to match the policy
	policy := account.Policies[0]
	policy.SourcePostureChecks = []string{accNetResourceRestrictPostureCheckID}

	// validate for peer1
	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate for peer2
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer2ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 0, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate routes for router1
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourceRouter1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.True(t, isRouter, "should be router")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 1, "expected source peers don't match")
	assert.NotNil(t, sourcePeers[accNetResourcePeer1ID], "expected source peers don't match")

	// validate rules for router1
	rules := account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers[accNetResourceRouter1ID], accNetResourceValidPeers, networkResourcesRoutes, account.GetResourcePoliciesMap())
	assert.Len(t, rules, 1, "expected rules count don't match")
	assert.Equal(t, uint16(80), rules[0].Port, "should have port 80")
	assert.Equal(t, "tcp", rules[0].Protocol, "should have protocol tcp")
	if !slices.Contains(rules[0].SourceRanges, accNetResourcePeer1IP.String()+"/32") {
		t.Errorf("%s should have source range of peer1 %s", rules[0].SourceRanges, accNetResourcePeer1IP.String())
	}
	if slices.Contains(rules[0].SourceRanges, accNetResourcePeer2IP.String()+"/32") {
		t.Errorf("%s should not have source range of peer2 %s", rules[0].SourceRanges, accNetResourcePeer2IP.String())
	}
}

func Test_NetworksNetMapGenWithNoMatchedPostureChecks(t *testing.T) {
	account := getBasicAccountsWithResource()

	// should not match any peer
	policy := account.Policies[0]
	policy.SourcePostureChecks = []string{accNetResourceLockedPostureCheckID}

	// validate for peer1
	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 0, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate for peer2
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer2ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 0, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate routes for router1
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourceRouter1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.True(t, isRouter, "should be router")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate rules for router1
	rules := account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers[accNetResourceRouter1ID], accNetResourceValidPeers, networkResourcesRoutes, account.GetResourcePoliciesMap())
	assert.Len(t, rules, 0, "expected rules count don't match")
}

func Test_NetworksNetMapGenWithTwoPoliciesAndPostureChecks(t *testing.T) {
	account := getBasicAccountsWithResource()

	// should allow peer1 to match the policy
	policy := account.Policies[0]
	policy.SourcePostureChecks = []string{accNetResourceRestrictPostureCheckID}

	// should allow peer1 and peer2 to match the policy
	newPolicy := &Policy{
		ID:        "policy2ID",
		AccountID: accID,
		Enabled:   true,
		Rules: []*PolicyRule{
			{
				ID:      "policy2ID",
				Enabled: true,
				Sources: []string{group1ID},
				DestinationResource: Resource{
					ID:   accNetResource1ID,
					Type: "Host",
				},
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
				Action:   PolicyTrafficActionAccept,
			},
		},
		SourcePostureChecks: []string{accNetResourceRelaxedPostureCheckID},
	}

	account.Policies = append(account.Policies, newPolicy)

	// validate for peer1
	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate for peer2
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer2ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate routes for router1
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourceRouter1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.True(t, isRouter, "should be router")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 2, "expected source peers don't match")
	assert.NotNil(t, sourcePeers[accNetResourcePeer1ID], "expected source peers don't match")
	assert.NotNil(t, sourcePeers[accNetResourcePeer2ID], "expected source peers don't match")

	// validate rules for router1
	rules := account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers[accNetResourceRouter1ID], accNetResourceValidPeers, networkResourcesRoutes, account.GetResourcePoliciesMap())
	assert.Len(t, rules, 2, "expected rules count don't match")
	assert.Equal(t, uint16(80), rules[0].Port, "should have port 80")
	assert.Equal(t, "tcp", rules[0].Protocol, "should have protocol tcp")
	if !slices.Contains(rules[0].SourceRanges, accNetResourcePeer1IP.String()+"/32") {
		t.Errorf("%s should have source range of peer1 %s", rules[0].SourceRanges, accNetResourcePeer1IP.String())
	}
	if slices.Contains(rules[0].SourceRanges, accNetResourcePeer2IP.String()+"/32") {
		t.Errorf("%s should not have source range of peer2 %s", rules[0].SourceRanges, accNetResourcePeer2IP.String())
	}

	assert.Equal(t, uint16(22), rules[1].Port, "should have port 22")
	assert.Equal(t, "tcp", rules[1].Protocol, "should have protocol tcp")
	if !slices.Contains(rules[1].SourceRanges, accNetResourcePeer1IP.String()+"/32") {
		t.Errorf("%s should have source range of peer1 %s", rules[1].SourceRanges, accNetResourcePeer1IP.String())
	}
	if !slices.Contains(rules[1].SourceRanges, accNetResourcePeer2IP.String()+"/32") {
		t.Errorf("%s should have source range of peer2 %s", rules[1].SourceRanges, accNetResourcePeer2IP.String())
	}
}

func Test_NetworksNetMapGenWithTwoPostureChecks(t *testing.T) {
	account := getBasicAccountsWithResource()

	// two posture checks should match only the peers that match both checks
	policy := account.Policies[0]
	policy.SourcePostureChecks = []string{accNetResourceRelaxedPostureCheckID, accNetResourceLinuxPostureCheckID}

	// validate for peer1
	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate for peer2
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourcePeer2ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.False(t, isRouter, "expected router status")
	assert.Len(t, networkResourcesRoutes, 0, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 0, "expected source peers don't match")

	// validate routes for router1
	isRouter, networkResourcesRoutes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourceRouter1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.True(t, isRouter, "should be router")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 1, "expected source peers don't match")
	assert.NotNil(t, sourcePeers[accNetResourcePeer1ID], "expected source peers don't match")

	// validate rules for router1
	rules := account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers[accNetResourceRouter1ID], accNetResourceValidPeers, networkResourcesRoutes, account.GetResourcePoliciesMap())
	assert.Len(t, rules, 1, "expected rules count don't match")
	assert.Equal(t, uint16(80), rules[0].Port, "should have port 80")
	assert.Equal(t, "tcp", rules[0].Protocol, "should have protocol tcp")
	if !slices.Contains(rules[0].SourceRanges, accNetResourcePeer1IP.String()+"/32") {
		t.Errorf("%s should have source range of peer1 %s", rules[0].SourceRanges, accNetResourcePeer1IP.String())
	}
	if slices.Contains(rules[0].SourceRanges, accNetResourcePeer2IP.String()+"/32") {
		t.Errorf("%s should not have source range of peer2 %s", rules[0].SourceRanges, accNetResourcePeer2IP.String())
	}
}

func Test_NetworksNetMapGenShouldExcludeOtherRouters(t *testing.T) {
	account := getBasicAccountsWithResource()

	account.Peers["router2Id"] = &nbpeer.Peer{Key: "router2Key", ID: "router2Id", AccountID: accID, IP: net.IP{192, 168, 1, 4}}
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID:        "router2Id",
		NetworkID: network1ID,
		AccountID: accID,
		Peer:      "router2Id",
	})

	// validate routes for router1
	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), accNetResourceRouter1ID, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap())
	assert.True(t, isRouter, "should be router")
	assert.Len(t, networkResourcesRoutes, 1, "expected network resource route don't match")
	assert.Len(t, sourcePeers, 2, "expected source peers don't match")
}
