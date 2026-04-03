package types

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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
			"groupAll": {
				ID:    "groupAll",
				Name:  "All",
				Peers: []string{"peer1", "peer2", "peer3", "peer11", "peer12", "peer21", "peer31", "peer32", "peer41", "peer51", "peer61"},
				Issued: GroupIssuedAPI,
			},
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

func Test_ExpandPortsAndRanges_SSHRuleExpansion(t *testing.T) {
	tests := []struct {
		name          string
		peer          *nbpeer.Peer
		rule          *PolicyRule
		base          FirewallRule
		expectedPorts []string
	}{
		{
			name: "adds port 22022 when SSH enabled on modern peer with port 22",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22", "22022"},
		},
		{
			name: "adds port 22022 once when port 22 is duplicated within policy",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22", "80", "22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22", "80", "22", "22022"},
		},
		{
			name: "does not add 22022 for peer with old version",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.59.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22"},
		},
		{
			name: "does not add 22022 when SSHEnabled is false",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: false,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22"},
		},
		{
			name: "does not add 22022 when ServerSSHAllowed is false",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: false},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22"},
		},
		{
			name: "does not add 22022 for UDP protocol",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolUDP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "udp"},
			expectedPorts: []string{"22"},
		},
		{
			name: "does not add 22022 when port 22 not in rule",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"80", "443"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"80", "443"},
		},
		{
			name: "does not duplicate 22022 when already present",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22", "22022"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22", "22022"},
		},
		{
			name: "does not duplicate 22022 when already within a port range",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol:   PolicyRuleProtocolTCP,
				PortRanges: []RulePortRange{{Start: 20, End: 32000}},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"20-32000"},
		},
		{
			name: "adds 22022 when port 22 in port range",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol:   PolicyRuleProtocolTCP,
				PortRanges: []RulePortRange{{Start: 20, End: 25}},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"20-25", "22022"},
		},
		{
			name: "adds single 22022 once when port 22 in multiple port ranges",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.60.0",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol:   PolicyRuleProtocolTCP,
				PortRanges: []RulePortRange{{Start: 20, End: 25}, {Start: 10, End: 100}},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"20-25", "10-100", "22022"},
		},
		{
			name: "dev suffix version supports all features",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "0.50.0-dev",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22", "22022"},
		},
		{
			name: "dev suffix version supports all features",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "dev",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22", "22022"},
		},
		{
			name: "development suffix version supports all features",
			peer: &nbpeer.Peer{
				ID:         "peer1",
				SSHEnabled: true,
				Meta: nbpeer.PeerSystemMeta{
					WtVersion: "development",
					Flags:     nbpeer.Flags{ServerSSHAllowed: true},
				},
			},
			rule: &PolicyRule{
				Protocol: PolicyRuleProtocolTCP,
				Ports:    []string{"22"},
			},
			base:          FirewallRule{PeerIP: "10.0.0.1", Direction: 0, Action: "accept", Protocol: "tcp"},
			expectedPorts: []string{"22", "22022"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPortsAndRanges(tt.base, tt.rule, tt.peer)

			var ports []string
			for _, fr := range result {
				if fr.Port != "" {
					ports = append(ports, fr.Port)
				} else if fr.PortRange.Start > 0 {
					ports = append(ports, fmt.Sprintf("%d-%d", fr.PortRange.Start, fr.PortRange.End))
				}
			}

			assert.Equal(t, tt.expectedPorts, ports, "expanded ports should match expected")
		})
	}
}

func Test_GetActiveGroupUsers(t *testing.T) {
	tests := []struct {
		name     string
		account  *Account
		expected map[string][]string
	}{
		{
			name: "all users are active",
			account: &Account{
				Users: map[string]*User{
					"user1": {
						Id:         "user1",
						AutoGroups: []string{"group1", "group2"},
						Blocked:    false,
					},
					"user2": {
						Id:         "user2",
						AutoGroups: []string{"group2", "group3"},
						Blocked:    false,
					},
					"user3": {
						Id:         "user3",
						AutoGroups: []string{"group1"},
						Blocked:    false,
					},
				},
			},
			expected: map[string][]string{
				"group1": {"user1", "user3"},
				"group2": {"user1", "user2"},
				"group3": {"user2"},
				"":       {"user1", "user2", "user3"},
			},
		},
		{
			name: "some users are blocked",
			account: &Account{
				Users: map[string]*User{
					"user1": {
						Id:         "user1",
						AutoGroups: []string{"group1", "group2"},
						Blocked:    false,
					},
					"user2": {
						Id:         "user2",
						AutoGroups: []string{"group2", "group3"},
						Blocked:    true,
					},
					"user3": {
						Id:         "user3",
						AutoGroups: []string{"group1", "group3"},
						Blocked:    false,
					},
				},
			},
			expected: map[string][]string{
				"group1": {"user1", "user3"},
				"group2": {"user1"},
				"group3": {"user3"},
				"":       {"user1", "user3"},
			},
		},
		{
			name: "all users are blocked",
			account: &Account{
				Users: map[string]*User{
					"user1": {
						Id:         "user1",
						AutoGroups: []string{"group1"},
						Blocked:    true,
					},
					"user2": {
						Id:         "user2",
						AutoGroups: []string{"group2"},
						Blocked:    true,
					},
				},
			},
			expected: map[string][]string{},
		},
		{
			name: "user with no auto groups",
			account: &Account{
				Users: map[string]*User{
					"user1": {
						Id:         "user1",
						AutoGroups: []string{},
						Blocked:    false,
					},
					"user2": {
						Id:         "user2",
						AutoGroups: []string{"group1"},
						Blocked:    false,
					},
				},
			},
			expected: map[string][]string{
				"group1": {"user2"},
				"":       {"user1", "user2"},
			},
		},
		{
			name: "empty account",
			account: &Account{
				Users: map[string]*User{},
			},
			expected: map[string][]string{},
		},
		{
			name: "multiple users in same group",
			account: &Account{
				Users: map[string]*User{
					"user1": {
						Id:         "user1",
						AutoGroups: []string{"group1"},
						Blocked:    false,
					},
					"user2": {
						Id:         "user2",
						AutoGroups: []string{"group1"},
						Blocked:    false,
					},
					"user3": {
						Id:         "user3",
						AutoGroups: []string{"group1"},
						Blocked:    false,
					},
				},
			},
			expected: map[string][]string{
				"group1": {"user1", "user2", "user3"},
				"":       {"user1", "user2", "user3"},
			},
		},
		{
			name: "user in multiple groups with blocked users",
			account: &Account{
				Users: map[string]*User{
					"user1": {
						Id:         "user1",
						AutoGroups: []string{"group1", "group2", "group3"},
						Blocked:    false,
					},
					"user2": {
						Id:         "user2",
						AutoGroups: []string{"group1", "group2"},
						Blocked:    true,
					},
					"user3": {
						Id:         "user3",
						AutoGroups: []string{"group3"},
						Blocked:    false,
					},
				},
			},
			expected: map[string][]string{
				"group1": {"user1"},
				"group2": {"user1"},
				"group3": {"user1", "user3"},
				"":       {"user1", "user3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.account.GetActiveGroupUsers()

			// Check that the number of groups matches
			assert.Equal(t, len(tt.expected), len(result), "number of groups should match")

			// Check each group's users
			for groupID, expectedUsers := range tt.expected {
				actualUsers, exists := result[groupID]
				assert.True(t, exists, "group %s should exist in result", groupID)
				assert.ElementsMatch(t, expectedUsers, actualUsers, "users in group %s should match", groupID)
			}

			// Ensure no extra groups in result
			for groupID := range result {
				_, exists := tt.expected[groupID]
				assert.True(t, exists, "unexpected group %s in result", groupID)
			}
		})
	}
}

func Test_FilterZoneRecordsForPeers(t *testing.T) {
	tests := []struct {
		name            string
		peer            *nbpeer.Peer
		customZone      nbdns.CustomZone
		peersToConnect  []*nbpeer.Peer
		expiredPeers    []*nbpeer.Peer
		expectedRecords []nbdns.SimpleRecord
	}{
		{
			name: "empty peers to connect",
			customZone: nbdns.CustomZone{
				Domain: "netbird.cloud.",
				Records: []nbdns.SimpleRecord{
					{Name: "peer1.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
					{Name: "router.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.100"},
				},
			},
			peersToConnect: []*nbpeer.Peer{},
			expiredPeers:   []*nbpeer.Peer{},
			peer:           &nbpeer.Peer{ID: "router", IP: net.ParseIP("10.0.0.100")},
			expectedRecords: []nbdns.SimpleRecord{
				{Name: "router.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.100"},
			},
		},
		{
			name: "multiple peers multiple records match",
			customZone: nbdns.CustomZone{
				Domain: "netbird.cloud.",
				Records: func() []nbdns.SimpleRecord {
					var records []nbdns.SimpleRecord
					for i := 1; i <= 100; i++ {
						records = append(records, nbdns.SimpleRecord{
							Name:  fmt.Sprintf("peer%d.netbird.cloud", i),
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: fmt.Sprintf("10.0.%d.%d", i/256, i%256),
						})
					}
					return records
				}(),
			},
			peersToConnect: func() []*nbpeer.Peer {
				var peers []*nbpeer.Peer
				for _, i := range []int{1, 5, 10, 25, 50, 75, 100} {
					peers = append(peers, &nbpeer.Peer{
						ID: fmt.Sprintf("peer%d", i),
						IP: net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
					})
				}
				return peers
			}(),
			expiredPeers: []*nbpeer.Peer{},
			peer:         &nbpeer.Peer{ID: "router", IP: net.ParseIP("10.0.0.100")},
			expectedRecords: func() []nbdns.SimpleRecord {
				var records []nbdns.SimpleRecord
				for _, i := range []int{1, 5, 10, 25, 50, 75, 100} {
					records = append(records, nbdns.SimpleRecord{
						Name:  fmt.Sprintf("peer%d.netbird.cloud", i),
						Type:  int(dns.TypeA),
						Class: nbdns.DefaultClass,
						TTL:   300,
						RData: fmt.Sprintf("10.0.%d.%d", i/256, i%256),
					})
				}
				return records
			}(),
		},
		{
			name: "peers with multiple DNS labels",
			customZone: nbdns.CustomZone{
				Domain: "netbird.cloud.",
				Records: []nbdns.SimpleRecord{
					{Name: "peer1.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
					{Name: "peer1-alt.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
					{Name: "peer1-backup.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
					{Name: "peer2.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
					{Name: "peer2-service.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
					{Name: "peer3.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.3"},
					{Name: "peer3-alt.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.3"},
					{Name: "router.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.100"},
				},
			},
			peersToConnect: []*nbpeer.Peer{
				{ID: "peer1", IP: net.ParseIP("10.0.0.1"), DNSLabel: "peer1", ExtraDNSLabels: []string{"peer1-alt", "peer1-backup"}},
				{ID: "peer2", IP: net.ParseIP("10.0.0.2"), DNSLabel: "peer2", ExtraDNSLabels: []string{"peer2-service"}},
			},
			expiredPeers: []*nbpeer.Peer{},
			peer:         &nbpeer.Peer{ID: "router", IP: net.ParseIP("10.0.0.100")},
			expectedRecords: []nbdns.SimpleRecord{
				{Name: "peer1.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "peer1-alt.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "peer1-backup.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "peer2.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
				{Name: "peer2-service.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
				{Name: "router.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.100"},
			},
		},
		{
			name: "expired peers are included in DNS entries",
			customZone: nbdns.CustomZone{
				Domain: "netbird.cloud.",
				Records: []nbdns.SimpleRecord{
					{Name: "peer1.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
					{Name: "peer2.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
					{Name: "expired-peer.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.99"},
					{Name: "router.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.100"},
				},
			},
			peersToConnect: []*nbpeer.Peer{
				{ID: "peer1", IP: net.ParseIP("10.0.0.1")},
			},
			expiredPeers: []*nbpeer.Peer{
				{ID: "expired-peer", IP: net.ParseIP("10.0.0.99")},
			},
			peer: &nbpeer.Peer{ID: "router", IP: net.ParseIP("10.0.0.100")},
			expectedRecords: []nbdns.SimpleRecord{
				{Name: "peer1.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "expired-peer.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.99"},
				{Name: "router.netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.100"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterZoneRecordsForPeers(tt.peer, tt.customZone, tt.peersToConnect, tt.expiredPeers)
			assert.Equal(t, len(tt.expectedRecords), len(result))
			assert.ElementsMatch(t, tt.expectedRecords, result)
		})
	}
}

func Test_filterPeerAppliedZones(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		accountZones []*zones.Zone
		peerGroups   LookupMap
		expected     []nbdns.CustomZone
	}{
		{
			name:         "empty peer groups returns empty custom zones",
			accountZones: []*zones.Zone{},
			peerGroups:   LookupMap{},
			expected:     []nbdns.CustomZone{},
		},
		{
			name: "peer has access to zone with A record",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "example.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.example.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "example.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.example.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "peer has access to zone with search domain enabled",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "internal.local",
					Enabled:            true,
					EnableSearchDomain: true,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "api.internal.local",
							Type:    records.RecordTypeA,
							Content: "10.0.0.1",
							TTL:     600,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "internal.local.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "api.internal.local.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   600,
							RData: "10.0.0.1",
						},
					},
					SearchDomainDisabled: false,
				},
			},
		},
		{
			name: "peer has no access to zone",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "private.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group2"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "secret.private.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected:   []nbdns.CustomZone{},
		},
		{
			name: "disabled zone is filtered out",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "disabled.com",
					Enabled:            false,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.disabled.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected:   []nbdns.CustomZone{},
		},
		{
			name: "zone with no records is filtered out",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "empty.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records:            []*records.Record{},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected:   []nbdns.CustomZone{},
		},
		{
			name: "peer has access via multiple groups",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "multi.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1", "group2", "group3"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.multi.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group2": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "multi.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.multi.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "multiple zones with mixed access",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "allowed.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.allowed.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
				{
					ID:                 "zone2",
					Domain:             "denied.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group2"},
					Records: []*records.Record{
						{
							ID:      "record2",
							Name:    "www.denied.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "allowed.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.allowed.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "zone with multiple record types",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "mixed.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.mixed.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
						{
							ID:      "record2",
							Name:    "ipv6.mixed.com",
							Type:    records.RecordTypeAAAA,
							Content: "2001:db8::1",
							TTL:     600,
						},
						{
							ID:      "record3",
							Name:    "alias.mixed.com",
							Type:    records.RecordTypeCNAME,
							Content: "www.mixed.com",
							TTL:     900,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "mixed.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.mixed.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
						{
							Name:  "ipv6.mixed.com.",
							Type:  int(dns.TypeAAAA),
							Class: nbdns.DefaultClass,
							TTL:   600,
							RData: "2001:db8::1",
						},
						{
							Name:  "alias.mixed.com.",
							Type:  int(dns.TypeCNAME),
							Class: nbdns.DefaultClass,
							TTL:   900,
							RData: "www.mixed.com.",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "multiple zones both accessible",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "first.com",
					Enabled:            true,
					EnableSearchDomain: true,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.first.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
				{
					ID:                 "zone2",
					Domain:             "second.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record2",
							Name:    "www.second.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     600,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "first.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.first.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: false,
				},
				{
					Domain: "second.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.second.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   600,
							RData: "192.168.1.2",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "zone with multiple records of same type",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "multi-a.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.multi-a.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
						{
							ID:      "record2",
							Name:    "www.multi-a.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "multi-a.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.multi-a.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
						{
							Name:  "www.multi-a.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.2",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "peer in multiple groups accessing different zones",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "zone1.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.zone1.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
				{
					ID:                 "zone2",
					Domain:             "zone2.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group2"},
					Records: []*records.Record{
						{
							ID:      "record2",
							Name:    "www.zone2.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: LookupMap{"group1": struct{}{}, "group2": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "zone1.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.zone1.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
				{
					Domain: "zone2.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.zone2.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.2",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterPeerAppliedZones(ctx, tt.accountZones, tt.peerGroups)
			require.Equal(t, len(tt.expected), len(result), "number of custom zones should match")

			for i, expectedZone := range tt.expected {
				assert.Equal(t, expectedZone.Domain, result[i].Domain, "domain should match")
				assert.Equal(t, expectedZone.SearchDomainDisabled, result[i].SearchDomainDisabled, "search domain disabled flag should match")
				assert.Equal(t, len(expectedZone.Records), len(result[i].Records), "number of records should match")

				for j, expectedRecord := range expectedZone.Records {
					assert.Equal(t, expectedRecord.Name, result[i].Records[j].Name, "record name should match")
					assert.Equal(t, expectedRecord.Type, result[i].Records[j].Type, "record type should match")
					assert.Equal(t, expectedRecord.Class, result[i].Records[j].Class, "record class should match")
					assert.Equal(t, expectedRecord.TTL, result[i].Records[j].TTL, "record TTL should match")
					assert.Equal(t, expectedRecord.RData, result[i].Records[j].RData, "record RData should match")
				}
			}
		})
	}
}
