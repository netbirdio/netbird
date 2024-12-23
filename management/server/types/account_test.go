package types

import (
	"testing"

	"github.com/stretchr/testify/require"

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
			},
			{
				ID:         "router2ID",
				NetworkID:  "network2ID",
				AccountID:  "accountID",
				Peer:       "peer2",
				PeerGroups: []string{},
				Masquerade: false,
				Metric:     100,
			},
			{
				ID:         "router3ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "peer3",
				PeerGroups: []string{},
				Masquerade: false,
				Metric:     100,
			},
			{
				ID:         "router4ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group1"},
				Masquerade: false,
				Metric:     100,
			},
			{
				ID:         "router5ID",
				NetworkID:  "network1ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group2", "group3"},
				Masquerade: false,
				Metric:     100,
			},
			{
				ID:         "router6ID",
				NetworkID:  "network2ID",
				AccountID:  "accountID",
				Peer:       "",
				PeerGroups: []string{"group4"},
				Masquerade: false,
				Metric:     100,
			},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID:        "resource1ID",
				AccountID: "accountID",
				NetworkID: "network1ID",
			},
			{
				ID:        "resource2ID",
				AccountID: "accountID",
				NetworkID: "network2ID",
			},
			{
				ID:        "resource3ID",
				AccountID: "accountID",
				NetworkID: "network1ID",
			},
			{
				ID:        "resource4ID",
				AccountID: "accountID",
				NetworkID: "network1ID",
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
}

func Test_GetResourcePoliciesMap(t *testing.T) {
	account := setupTestAccount()
	policies := account.GetResourcePoliciesMap()
	require.Equal(t, 4, len(policies))
	require.Equal(t, 1, len(policies["resource1ID"]))
	require.Equal(t, 1, len(policies["resource2ID"]))
	require.Equal(t, 2, len(policies["resource3ID"]))
	require.Equal(t, 1, len(policies["resource4ID"]))
}

func Test_AddNetworksRoutingPeersAddsMissingPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer2Key"},
		{Peer: "peer3Key"},
	}
	peersToConnect := []*nbpeer.Peer{
		{Key: "peer2Key"},
	}
	expiredPeers := []*nbpeer.Peer{
		{Key: "peer4Key"},
	}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, []string{})
	require.Len(t, result, 2)
	require.Equal(t, "peer2Key", result[0].Key)
	require.Equal(t, "peer3Key", result[1].Key)
}

func Test_AddNetworksRoutingPeersIgnoresExistingPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer2Key"},
	}
	peersToConnect := []*nbpeer.Peer{
		{Key: "peer2Key"},
	}
	expiredPeers := []*nbpeer.Peer{}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, []string{})
	require.Len(t, result, 1)
	require.Equal(t, "peer2Key", result[0].Key)
}

func Test_AddNetworksRoutingPeersAddsExpiredPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1Key"}
	networkResourcesRoutes := []*route.Route{
		{Peer: "peer2Key"},
		{Peer: "peer3Key"},
	}
	peersToConnect := []*nbpeer.Peer{
		{Key: "peer2Key"},
	}
	expiredPeers := []*nbpeer.Peer{
		{Key: "peer3Key"},
	}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, []string{})
	require.Len(t, result, 1)
	require.Equal(t, "peer2Key", result[0].Key)
}

func Test_AddNetworksRoutingPeersHandlesNoMissingPeers(t *testing.T) {
	account := setupTestAccount()
	peer := &nbpeer.Peer{Key: "peer1"}
	networkResourcesRoutes := []*route.Route{}
	peersToConnect := []*nbpeer.Peer{}
	expiredPeers := []*nbpeer.Peer{}

	result := account.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, false, []string{})
	require.Len(t, result, 0)
}
