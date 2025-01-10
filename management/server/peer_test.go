package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/util"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/proto"
	nbAccount "github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
)

func TestPeer_LoginExpired(t *testing.T) {
	tt := []struct {
		name              string
		expirationEnabled bool
		lastLogin         time.Time
		expected          bool
		accountSettings   *types.Settings
	}{
		{
			name:              "Peer Login Expiration Disabled. Peer Login Should Not Expire",
			expirationEnabled: false,
			lastLogin:         time.Now().UTC().Add(-25 * time.Hour),
			accountSettings: &types.Settings{
				PeerLoginExpirationEnabled: true,
				PeerLoginExpiration:        time.Hour,
			},
			expected: false,
		},
		{
			name:              "Peer Login Should Expire",
			expirationEnabled: true,
			lastLogin:         time.Now().UTC().Add(-25 * time.Hour),
			accountSettings: &types.Settings{
				PeerLoginExpirationEnabled: true,
				PeerLoginExpiration:        time.Hour,
			},
			expected: true,
		},
		{
			name:              "Peer Login Should Not Expire",
			expirationEnabled: true,
			lastLogin:         time.Now().UTC(),
			accountSettings: &types.Settings{
				PeerLoginExpirationEnabled: true,
				PeerLoginExpiration:        time.Hour,
			},
			expected: false,
		},
	}

	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			peer := &nbpeer.Peer{
				LoginExpirationEnabled: c.expirationEnabled,
				LastLogin:              util.ToPtr(c.lastLogin),
				UserID:                 userID,
			}

			expired, _ := peer.LoginExpired(c.accountSettings.PeerLoginExpiration)
			assert.Equal(t, expired, c.expected)
		})
	}
}

func TestPeer_SessionExpired(t *testing.T) {
	tt := []struct {
		name              string
		expirationEnabled bool
		lastLogin         time.Time
		connected         bool
		expected          bool
		accountSettings   *types.Settings
	}{
		{
			name:              "Peer Inactivity Expiration Disabled. Peer Inactivity Should Not Expire",
			expirationEnabled: false,
			connected:         false,
			lastLogin:         time.Now().UTC().Add(-1 * time.Second),
			accountSettings: &types.Settings{
				PeerInactivityExpirationEnabled: true,
				PeerInactivityExpiration:        time.Hour,
			},
			expected: false,
		},
		{
			name:              "Peer Inactivity Should Expire",
			expirationEnabled: true,
			connected:         false,
			lastLogin:         time.Now().UTC().Add(-1 * time.Second),
			accountSettings: &types.Settings{
				PeerInactivityExpirationEnabled: true,
				PeerInactivityExpiration:        time.Second,
			},
			expected: true,
		},
		{
			name:              "Peer Inactivity Should Not Expire",
			expirationEnabled: true,
			connected:         true,
			lastLogin:         time.Now().UTC(),
			accountSettings: &types.Settings{
				PeerInactivityExpirationEnabled: true,
				PeerInactivityExpiration:        time.Second,
			},
			expected: false,
		},
	}

	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			peerStatus := &nbpeer.PeerStatus{
				Connected: c.connected,
			}
			peer := &nbpeer.Peer{
				InactivityExpirationEnabled: c.expirationEnabled,
				LastLogin:                   util.ToPtr(c.lastLogin),
				Status:                      peerStatus,
				UserID:                      userID,
			}

			expired, _ := peer.SessionExpired(c.accountSettings.PeerInactivityExpiration)
			assert.Equal(t, expired, c.expected)
		})
	}
}

func TestAccountManager_GetNetworkMap(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	account, err := createAccount(manager, expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userId, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	_, _, _, err = manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	networkMap, err := manager.GetNetworkMap(context.Background(), peer1.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap.Peers) != 1 {
		t.Errorf("expecting Account NetworkMap to have 1 peers, got %v", len(networkMap.Peers))
		return
	}

	if networkMap.Peers[0].Key != peerKey2.PublicKey().String() {
		t.Errorf(
			"expecting Account NetworkMap to have peer with a key %s, got %s",
			peerKey2.PublicKey().String(),
			networkMap.Peers[0].Key,
		)
	}
}

func TestAccountManager_GetNetworkMapWithPolicy(t *testing.T) {
	// TODO: disable until we start use policy again
	t.Skip()
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedID := "test_account"
	userID := "account_creator"
	account, err := createAccount(manager, expectedID, userID, "")
	if err != nil {
		t.Fatal(err)
	}

	var setupKey *types.SetupKey
	for _, key := range account.SetupKeys {
		if key.Type == types.SetupKeyReusable {
			setupKey = key
		}
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	peer2, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	policies, err := manager.ListPolicies(context.Background(), account.Id, userID)
	if err != nil {
		t.Errorf("expecting to get a list of rules, got failure %v", err)
		return
	}

	err = manager.DeletePolicy(context.Background(), account.Id, policies[0].ID, userID)
	if err != nil {
		t.Errorf("expecting to delete 1 group, got failure %v", err)
		return
	}
	var (
		group1 types.Group
		group2 types.Group
	)

	group1.ID = xid.New().String()
	group2.ID = xid.New().String()
	group1.Name = "src"
	group2.Name = "dst"
	group1.Peers = append(group1.Peers, peer1.ID)
	group2.Peers = append(group2.Peers, peer2.ID)

	err = manager.SaveGroup(context.Background(), account.Id, userID, &group1)
	if err != nil {
		t.Errorf("expecting group1 to be added, got failure %v", err)
		return
	}
	err = manager.SaveGroup(context.Background(), account.Id, userID, &group2)
	if err != nil {
		t.Errorf("expecting group2 to be added, got failure %v", err)
		return
	}

	policy := &types.Policy{
		Name:    "test",
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{group1.ID},
				Destinations:  []string{group2.ID},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}
	policy, err = manager.SavePolicy(context.Background(), account.Id, userID, policy)
	if err != nil {
		t.Errorf("expecting rule to be added, got failure %v", err)
		return
	}

	networkMap1, err := manager.GetNetworkMap(context.Background(), peer1.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap1.Peers) != 1 {
		t.Errorf(
			"expecting Account NetworkMap to have 1 peers, got %v: %v",
			len(networkMap1.Peers),
			networkMap1.Peers,
		)
		return
	}

	if networkMap1.Peers[0].Key != peerKey2.PublicKey().String() {
		t.Errorf(
			"expecting Account NetworkMap to have peer with a key %s, got %s",
			peerKey2.PublicKey().String(),
			networkMap1.Peers[0].Key,
		)
	}

	networkMap2, err := manager.GetNetworkMap(context.Background(), peer2.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap2.Peers) != 1 {
		t.Errorf("expecting Account NetworkMap to have 1 peers, got %v", len(networkMap2.Peers))
	}

	if len(networkMap2.Peers) > 0 && networkMap2.Peers[0].Key != peerKey1.PublicKey().String() {
		t.Errorf(
			"expecting Account NetworkMap to have peer with a key %s, got %s",
			peerKey1.PublicKey().String(),
			networkMap2.Peers[0].Key,
		)
	}

	policy.Enabled = false
	_, err = manager.SavePolicy(context.Background(), account.Id, userID, policy)
	if err != nil {
		t.Errorf("expecting rule to be added, got failure %v", err)
		return
	}

	networkMap1, err = manager.GetNetworkMap(context.Background(), peer1.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap1.Peers) != 0 {
		t.Errorf(
			"expecting Account NetworkMap to have 0 peers, got %v: %v",
			len(networkMap1.Peers),
			networkMap1.Peers,
		)
		return
	}

	networkMap2, err = manager.GetNetworkMap(context.Background(), peer2.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap2.Peers) != 0 {
		t.Errorf("expecting Account NetworkMap to have 0 peers, got %v", len(networkMap2.Peers))
	}
}

func TestAccountManager_GetPeerNetwork(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	account, err := createAccount(manager, expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userId, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	_, _, _, err = manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	network, err := manager.GetPeerNetwork(context.Background(), peer1.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Network.Identifier != network.Identifier {
		t.Errorf("expecting Account Networks ID to be equal, got %s expected %s", network.Identifier, account.Network.Identifier)
	}
}

func TestDefaultAccountManager_GetPeer(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	// account with an admin and a regular user
	accountID := "test_account"
	adminUser := "account_creator"
	someUser := "some_user"
	account := newAccountWithId(context.Background(), accountID, adminUser, "")
	account.Users[someUser] = &types.User{
		Id:   someUser,
		Role: types.UserRoleUser,
	}
	account.Settings.RegularUsersViewBlocked = false

	err = manager.Store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatal(err)
		return
	}

	// two peers one added by a regular user and one with a setup key
	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, adminUser, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), "", someUser, &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	// the second peer added with a setup key
	peer2, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	})
	if err != nil {
		t.Fatal(err)
		return
	}

	// the user can see its own peer
	peer, err := manager.GetPeer(context.Background(), accountID, peer1.ID, someUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

	// the user can see peer2 because peer1 of the user has access to peer2 due to the All group and the default rule 0 all-to-all access
	peer, err = manager.GetPeer(context.Background(), accountID, peer2.ID, someUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

	// delete the all-to-all policy so that user's peer1 has no access to peer2
	for _, policy := range account.Policies {
		err = manager.DeletePolicy(context.Background(), accountID, policy.ID, adminUser)
		if err != nil {
			t.Fatal(err)
			return
		}
	}

	// at this point the user can't see the details of peer2
	peer, err = manager.GetPeer(context.Background(), accountID, peer2.ID, someUser) //nolint
	assert.Error(t, err)

	// admin users can always access all the peers
	peer, err = manager.GetPeer(context.Background(), accountID, peer1.ID, adminUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

	peer, err = manager.GetPeer(context.Background(), accountID, peer2.ID, adminUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)
}

func TestDefaultAccountManager_GetPeers(t *testing.T) {
	testCases := []struct {
		name                string
		role                types.UserRole
		limitedViewSettings bool
		isServiceUser       bool
		expectedPeerCount   int
	}{
		{
			name:                "Regular user, no limited view settings, not a service user",
			role:                types.UserRoleUser,
			limitedViewSettings: false,
			isServiceUser:       false,
			expectedPeerCount:   1,
		},
		{
			name:                "Service user, no limited view settings",
			role:                types.UserRoleUser,
			limitedViewSettings: false,
			isServiceUser:       true,
			expectedPeerCount:   2,
		},
		{
			name:                "Regular user, limited view settings",
			role:                types.UserRoleUser,
			limitedViewSettings: true,
			isServiceUser:       false,
			expectedPeerCount:   0,
		},
		{
			name:                "Service user, limited view settings",
			role:                types.UserRoleUser,
			limitedViewSettings: true,
			isServiceUser:       true,
			expectedPeerCount:   2,
		},
		{
			name:                "Admin, no limited view settings, not a service user",
			role:                types.UserRoleAdmin,
			limitedViewSettings: false,
			isServiceUser:       false,
			expectedPeerCount:   2,
		},
		{
			name:                "Admin service user, no limited view settings",
			role:                types.UserRoleAdmin,
			limitedViewSettings: false,
			isServiceUser:       true,
			expectedPeerCount:   2,
		},
		{
			name:                "Admin, limited view settings",
			role:                types.UserRoleAdmin,
			limitedViewSettings: true,
			isServiceUser:       false,
			expectedPeerCount:   2,
		},
		{
			name:                "Admin Service user, limited view settings",
			role:                types.UserRoleAdmin,
			limitedViewSettings: true,
			isServiceUser:       true,
			expectedPeerCount:   2,
		},
		{
			name:                "Owner, no limited view settings",
			role:                types.UserRoleOwner,
			limitedViewSettings: true,
			isServiceUser:       false,
			expectedPeerCount:   2,
		},
		{
			name:                "Owner, limited view settings",
			role:                types.UserRoleOwner,
			limitedViewSettings: true,
			isServiceUser:       false,
			expectedPeerCount:   2,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			manager, err := createManager(t)
			if err != nil {
				t.Fatal(err)
				return
			}

			// account with an admin and a regular user
			accountID := "test_account"
			adminUser := "account_creator"
			someUser := "some_user"
			account := newAccountWithId(context.Background(), accountID, adminUser, "")
			account.Users[someUser] = &types.User{
				Id:            someUser,
				Role:          testCase.role,
				IsServiceUser: testCase.isServiceUser,
			}
			account.Policies = []*types.Policy{}
			account.Settings.RegularUsersViewBlocked = testCase.limitedViewSettings

			err = manager.Store.SaveAccount(context.Background(), account)
			if err != nil {
				t.Fatal(err)
				return
			}

			peerKey1, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
				return
			}

			peerKey2, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
				return
			}

			_, _, _, err = manager.AddPeer(context.Background(), "", someUser, &nbpeer.Peer{
				Key:  peerKey1.PublicKey().String(),
				Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
			})
			if err != nil {
				t.Errorf("expecting peer to be added, got failure %v", err)
				return
			}

			_, _, _, err = manager.AddPeer(context.Background(), "", adminUser, &nbpeer.Peer{
				Key:  peerKey2.PublicKey().String(),
				Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
			})
			if err != nil {
				t.Errorf("expecting peer to be added, got failure %v", err)
				return
			}

			peers, err := manager.GetPeers(context.Background(), accountID, someUser)
			if err != nil {
				t.Fatal(err)
				return
			}
			assert.NotNil(t, peers)

			assert.Len(t, peers, testCase.expectedPeerCount)

		})
	}
}

func setupTestAccountManager(b *testing.B, peers int, groups int) (*DefaultAccountManager, string, string, error) {
	b.Helper()

	manager, err := createManager(b)
	if err != nil {
		return nil, "", "", err
	}

	accountID := "test_account"
	adminUser := "account_creator"
	regularUser := "regular_user"

	account := newAccountWithId(context.Background(), accountID, adminUser, "")
	account.Users[regularUser] = &types.User{
		Id:   regularUser,
		Role: types.UserRoleUser,
	}

	// Create peers
	for i := 0; i < peers; i++ {
		peerKey, _ := wgtypes.GeneratePrivateKey()
		peer := &nbpeer.Peer{
			ID:       fmt.Sprintf("peer-%d", i),
			DNSLabel: fmt.Sprintf("peer-%d", i),
			Key:      peerKey.PublicKey().String(),
			IP:       net.ParseIP(fmt.Sprintf("100.64.%d.%d", i/256, i%256)),
			Status:   &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
			UserID:   regularUser,
		}
		account.Peers[peer.ID] = peer
	}

	// Create groups and policies
	account.Policies = make([]*types.Policy, 0, groups)
	for i := 0; i < groups; i++ {
		groupID := fmt.Sprintf("group-%d", i)
		group := &types.Group{
			ID:   groupID,
			Name: fmt.Sprintf("Group %d", i),
		}
		for j := 0; j < peers/groups; j++ {
			peerIndex := i*(peers/groups) + j
			group.Peers = append(group.Peers, fmt.Sprintf("peer-%d", peerIndex))
		}

		// Create network, router and resource for this group
		network := &networkTypes.Network{
			ID:        fmt.Sprintf("network-%d", i),
			AccountID: account.Id,
			Name:      fmt.Sprintf("Network for Group %d", i),
		}
		account.Networks = append(account.Networks, network)

		ips := account.GetTakenIPs()
		peerIP, err := types.AllocatePeerIP(account.Network.Net, ips)
		if err != nil {
			return nil, "", "", err
		}

		peerKey, _ := wgtypes.GeneratePrivateKey()
		peer := &nbpeer.Peer{
			ID:       fmt.Sprintf("peer-nr-%d", len(account.Peers)+1),
			DNSLabel: fmt.Sprintf("peer-nr-%d", len(account.Peers)+1),
			Key:      peerKey.PublicKey().String(),
			IP:       peerIP,
			Status:   &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
			UserID:   regularUser,
			Meta: nbpeer.PeerSystemMeta{
				Hostname:  fmt.Sprintf("peer-nr-%d", len(account.Peers)+1),
				GoOS:      "linux",
				Kernel:    "Linux",
				Core:      "21.04",
				Platform:  "x86_64",
				OS:        "Ubuntu",
				WtVersion: "development",
				UIVersion: "development",
			},
		}
		account.Peers[peer.ID] = peer

		group.Peers = append(group.Peers, peer.ID)
		account.Groups[groupID] = group

		router := &routerTypes.NetworkRouter{
			ID:         fmt.Sprintf("network-router-%d", i),
			NetworkID:  network.ID,
			AccountID:  account.Id,
			Peer:       peer.ID,
			PeerGroups: []string{},
			Masquerade: false,
			Metric:     9999,
		}
		account.NetworkRouters = append(account.NetworkRouters, router)

		resource := &resourceTypes.NetworkResource{
			ID:        fmt.Sprintf("network-resource-%d", i),
			NetworkID: network.ID,
			AccountID: account.Id,
			Name:      fmt.Sprintf("Network resource for Group %d", i),
			Type:      "host",
			Address:   "192.0.2.0/32",
		}
		account.NetworkResources = append(account.NetworkResources, resource)

		// Create a policy for this network resource
		nrPolicy := &types.Policy{
			ID:      fmt.Sprintf("policy-nr-%d", i),
			Name:    fmt.Sprintf("Policy for network resource %d", i),
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					ID:           fmt.Sprintf("rule-nr-%d", i),
					Name:         fmt.Sprintf("Rule for network resource %d", i),
					Enabled:      true,
					Sources:      []string{groupID},
					Destinations: []string{},
					DestinationResource: types.Resource{
						ID: resource.ID,
					},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}
		account.Policies = append(account.Policies, nrPolicy)

		// Create a policy for this group
		policy := &types.Policy{
			ID:      fmt.Sprintf("policy-%d", i),
			Name:    fmt.Sprintf("Policy for Group %d", i),
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					ID:            fmt.Sprintf("rule-%d", i),
					Name:          fmt.Sprintf("Rule for Group %d", i),
					Enabled:       true,
					Sources:       []string{groupID},
					Destinations:  []string{groupID},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}
		account.Policies = append(account.Policies, policy)
	}

	account.PostureChecks = []*posture.Checks{
		{
			ID:   "PostureChecksAll",
			Name: "All",
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "0.0.1",
				},
			},
		},
	}

	err = manager.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, "", "", err
	}

	return manager, accountID, regularUser, nil
}

func BenchmarkGetPeers(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Small", 50, 5},
		{"Medium", 500, 10},
		{"Large", 5000, 20},
		{"Small single", 50, 1},
		{"Medium single", 500, 1},
		{"Large 5", 5000, 5},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, accountID, userID, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := manager.GetPeers(context.Background(), accountID, userID)
				if err != nil {
					b.Fatalf("GetPeers failed: %v", err)
				}
			}
		})
	}
}
func BenchmarkUpdateAccountPeers(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 90, 120, 90, 120},
		{"Medium", 500, 100, 110, 150, 120, 260},
		{"Large", 5000, 200, 800, 1700, 2500, 5000},
		{"Small single", 50, 10, 90, 120, 90, 120},
		{"Medium single", 500, 10, 110, 170, 120, 200},
		{"Large 5", 5000, 15, 1300, 2100, 4900, 7000},
		{"Extra Large", 2000, 2000, 1300, 2400, 3900, 6400},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}

			ctx := context.Background()

			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}

			peerChannels := make(map[string]chan *UpdateMessage)

			for peerID := range account.Peers {
				peerChannels[peerID] = make(chan *UpdateMessage, channelBufferSize)
			}

			manager.peersUpdateManager.peerChannels = peerChannels

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				manager.UpdateAccountPeers(ctx, account.Id)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			minExpected := bc.minMsPerOpLocal
			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				minExpected = bc.minMsPerOpCICD
				maxExpected = bc.maxMsPerOpCICD
			}

			if msPerOp < minExpected {
				b.Fatalf("Benchmark %s failed: too fast (%.2f ms/op, minimum %.2f ms/op)", bc.name, msPerOp, minExpected)
			}

			if msPerOp > (maxExpected * 1.1) {
				b.Fatalf("Benchmark %s failed: too slow (%.2f ms/op, maximum %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func TestToSyncResponse(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	domainList, err := domain.FromStringList([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		Signal: &Host{
			Proto:    "https",
			URI:      "signal.uri",
			Username: "",
			Password: "",
		},
		Stuns: []*Host{{URI: "stun.uri", Proto: UDP}},
		TURNConfig: &TURNConfig{
			Turns: []*Host{{URI: "turn.uri", Proto: UDP, Username: "turn-user", Password: "turn-pass"}},
		},
	}
	peer := &nbpeer.Peer{
		IP:         net.ParseIP("192.168.1.1"),
		SSHEnabled: true,
		Key:        "peer-key",
		DNSLabel:   "peer1",
		SSHKey:     "peer1-ssh-key",
	}
	turnRelayToken := &Token{
		Payload:   "turn-user",
		Signature: "turn-pass",
	}
	networkMap := &types.NetworkMap{
		Network:      &types.Network{Net: *ipnet, Serial: 1000},
		Peers:        []*nbpeer.Peer{{IP: net.ParseIP("192.168.1.2"), Key: "peer2-key", DNSLabel: "peer2", SSHEnabled: true, SSHKey: "peer2-ssh-key"}},
		OfflinePeers: []*nbpeer.Peer{{IP: net.ParseIP("192.168.1.3"), Key: "peer3-key", DNSLabel: "peer3", SSHEnabled: true, SSHKey: "peer3-ssh-key"}},
		Routes: []*nbroute.Route{
			{
				ID:          "route1",
				Network:     netip.MustParsePrefix("10.0.0.0/24"),
				Domains:     domainList,
				KeepRoute:   true,
				NetID:       "route1",
				Peer:        "peer1",
				NetworkType: 1,
				Masquerade:  true,
				Metric:      9999,
				Enabled:     true,
			},
		},
		DNSConfig: nbdns.Config{
			ServiceEnable: true,
			NameServerGroups: []*nbdns.NameServerGroup{
				{
					NameServers: []nbdns.NameServer{{
						IP:     netip.MustParseAddr("8.8.8.8"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					}},
					Primary:              true,
					Domains:              []string{"example.com"},
					Enabled:              true,
					SearchDomainsEnabled: true,
				},
				{
					ID: "ns1",
					NameServers: []nbdns.NameServer{{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					}},
					Groups:               []string{"group1"},
					Primary:              true,
					Domains:              []string{"example.com"},
					Enabled:              true,
					SearchDomainsEnabled: true,
				},
			},
			CustomZones: []nbdns.CustomZone{{Domain: "example.com", Records: []nbdns.SimpleRecord{{Name: "example.com", Type: 1, Class: "IN", TTL: 60, RData: "100.64.0.1"}}}},
		},
		FirewallRules: []*types.FirewallRule{
			{PeerIP: "192.168.1.2", Direction: types.FirewallRuleDirectionIN, Action: string(types.PolicyTrafficActionAccept), Protocol: string(types.PolicyRuleProtocolTCP), Port: "80"},
		},
	}
	dnsName := "example.com"
	checks := []*posture.Checks{
		{
			Checks: posture.ChecksDefinition{
				ProcessCheck: &posture.ProcessCheck{
					Processes: []posture.Process{{LinuxPath: "/usr/bin/netbird"}},
				},
			},
		},
	}
	dnsCache := &DNSConfigCache{}

	response := toSyncResponse(context.Background(), config, peer, turnRelayToken, turnRelayToken, networkMap, dnsName, checks, dnsCache, true)

	assert.NotNil(t, response)
	// assert peer config
	assert.Equal(t, "192.168.1.1/24", response.PeerConfig.Address)
	assert.Equal(t, "peer1.example.com", response.PeerConfig.Fqdn)
	assert.Equal(t, true, response.PeerConfig.SshConfig.SshEnabled)
	// assert wiretrustee config
	assert.Equal(t, "signal.uri", response.WiretrusteeConfig.Signal.Uri)
	assert.Equal(t, proto.HostConfig_HTTPS, response.WiretrusteeConfig.Signal.GetProtocol())
	assert.Equal(t, "stun.uri", response.WiretrusteeConfig.Stuns[0].Uri)
	assert.Equal(t, "turn.uri", response.WiretrusteeConfig.Turns[0].HostConfig.GetUri())
	assert.Equal(t, "turn-user", response.WiretrusteeConfig.Turns[0].User)
	assert.Equal(t, "turn-pass", response.WiretrusteeConfig.Turns[0].Password)
	// assert RemotePeers
	assert.Equal(t, 1, len(response.RemotePeers))
	assert.Equal(t, "192.168.1.2/32", response.RemotePeers[0].AllowedIps[0])
	assert.Equal(t, "peer2-key", response.RemotePeers[0].WgPubKey)
	assert.Equal(t, "peer2.example.com", response.RemotePeers[0].GetFqdn())
	assert.Equal(t, false, response.RemotePeers[0].GetSshConfig().GetSshEnabled())
	assert.Equal(t, []byte("peer2-ssh-key"), response.RemotePeers[0].GetSshConfig().GetSshPubKey())
	// assert network map
	assert.Equal(t, uint64(1000), response.NetworkMap.Serial)
	assert.Equal(t, "192.168.1.1/24", response.NetworkMap.PeerConfig.Address)
	assert.Equal(t, "peer1.example.com", response.NetworkMap.PeerConfig.Fqdn)
	assert.Equal(t, true, response.NetworkMap.PeerConfig.SshConfig.SshEnabled)
	// assert network map RemotePeers
	assert.Equal(t, 1, len(response.NetworkMap.RemotePeers))
	assert.Equal(t, "192.168.1.2/32", response.NetworkMap.RemotePeers[0].AllowedIps[0])
	assert.Equal(t, "peer2-key", response.NetworkMap.RemotePeers[0].WgPubKey)
	assert.Equal(t, "peer2.example.com", response.NetworkMap.RemotePeers[0].GetFqdn())
	assert.Equal(t, []byte("peer2-ssh-key"), response.NetworkMap.RemotePeers[0].GetSshConfig().GetSshPubKey())
	// assert network map OfflinePeers
	assert.Equal(t, 1, len(response.NetworkMap.OfflinePeers))
	assert.Equal(t, "192.168.1.3/32", response.NetworkMap.OfflinePeers[0].AllowedIps[0])
	assert.Equal(t, "peer3-key", response.NetworkMap.OfflinePeers[0].WgPubKey)
	assert.Equal(t, "peer3.example.com", response.NetworkMap.OfflinePeers[0].GetFqdn())
	assert.Equal(t, []byte("peer3-ssh-key"), response.NetworkMap.OfflinePeers[0].GetSshConfig().GetSshPubKey())
	// assert network map Routes
	assert.Equal(t, 1, len(response.NetworkMap.Routes))
	assert.Equal(t, "10.0.0.0/24", response.NetworkMap.Routes[0].Network)
	assert.Equal(t, "route1", response.NetworkMap.Routes[0].ID)
	assert.Equal(t, "peer1", response.NetworkMap.Routes[0].Peer)
	assert.Equal(t, "example.com", response.NetworkMap.Routes[0].Domains[0])
	assert.Equal(t, true, response.NetworkMap.Routes[0].KeepRoute)
	assert.Equal(t, true, response.NetworkMap.Routes[0].Masquerade)
	assert.Equal(t, int64(9999), response.NetworkMap.Routes[0].Metric)
	assert.Equal(t, int64(1), response.NetworkMap.Routes[0].NetworkType)
	assert.Equal(t, "route1", response.NetworkMap.Routes[0].NetID)
	// assert network map DNSConfig
	assert.Equal(t, true, response.NetworkMap.DNSConfig.ServiceEnable)
	assert.Equal(t, 1, len(response.NetworkMap.DNSConfig.CustomZones))
	assert.Equal(t, 2, len(response.NetworkMap.DNSConfig.NameServerGroups))
	// assert network map DNSConfig.CustomZones
	assert.Equal(t, "example.com", response.NetworkMap.DNSConfig.CustomZones[0].Domain)
	assert.Equal(t, 1, len(response.NetworkMap.DNSConfig.CustomZones[0].Records))
	assert.Equal(t, "example.com", response.NetworkMap.DNSConfig.CustomZones[0].Records[0].Name)
	assert.Equal(t, int64(1), response.NetworkMap.DNSConfig.CustomZones[0].Records[0].Type)
	assert.Equal(t, "IN", response.NetworkMap.DNSConfig.CustomZones[0].Records[0].Class)
	assert.Equal(t, int64(60), response.NetworkMap.DNSConfig.CustomZones[0].Records[0].TTL)
	assert.Equal(t, "100.64.0.1", response.NetworkMap.DNSConfig.CustomZones[0].Records[0].RData)
	// assert network map DNSConfig.NameServerGroups
	assert.Equal(t, true, response.NetworkMap.DNSConfig.NameServerGroups[0].Primary)
	assert.Equal(t, true, response.NetworkMap.DNSConfig.NameServerGroups[0].SearchDomainsEnabled)
	assert.Equal(t, "example.com", response.NetworkMap.DNSConfig.NameServerGroups[0].Domains[0])
	assert.Equal(t, "8.8.8.8", response.NetworkMap.DNSConfig.NameServerGroups[0].NameServers[0].GetIP())
	assert.Equal(t, int64(1), response.NetworkMap.DNSConfig.NameServerGroups[0].NameServers[0].GetNSType())
	assert.Equal(t, int64(53), response.NetworkMap.DNSConfig.NameServerGroups[0].NameServers[0].GetPort())
	// assert network map Firewall
	assert.Equal(t, 1, len(response.NetworkMap.FirewallRules))
	assert.Equal(t, "192.168.1.2", response.NetworkMap.FirewallRules[0].PeerIP)
	assert.Equal(t, proto.RuleDirection_IN, response.NetworkMap.FirewallRules[0].Direction)
	assert.Equal(t, proto.RuleAction_ACCEPT, response.NetworkMap.FirewallRules[0].Action)
	assert.Equal(t, proto.RuleProtocol_TCP, response.NetworkMap.FirewallRules[0].Protocol)
	assert.Equal(t, "80", response.NetworkMap.FirewallRules[0].Port)
	// assert posture checks
	assert.Equal(t, 1, len(response.Checks))
	assert.Equal(t, "/usr/bin/netbird", response.Checks[0].Files[0])
}

func Test_RegisterPeerByUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	assert.NoError(t, err)

	am, err := BuildManager(context.Background(), s, NewPeersUpdateManager(nil), nil, "", "netbird.cloud", eventStore, nil, false, MocIntegratedValidator{}, metrics)
	assert.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	existingUserID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	_, err = s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	newPeer := &nbpeer.Peer{
		ID:        xid.New().String(),
		AccountID: existingAccountID,
		Key:       "newPeerKey",
		IP:        net.IP{123, 123, 123, 123},
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "newPeer",
			GoOS:     "linux",
		},
		Name:       "newPeerName",
		DNSLabel:   "newPeer.test",
		UserID:     existingUserID,
		Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
		SSHEnabled: false,
		LastLogin:  util.ToPtr(time.Now()),
	}

	addedPeer, _, _, err := am.AddPeer(context.Background(), "", existingUserID, newPeer)
	require.NoError(t, err)

	peer, err := s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthShare, addedPeer.Key)
	require.NoError(t, err)
	assert.Equal(t, peer.AccountID, existingAccountID)
	assert.Equal(t, peer.UserID, existingUserID)

	account, err := s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)
	assert.Contains(t, account.Peers, addedPeer.ID)
	assert.Equal(t, peer.Meta.Hostname, newPeer.Meta.Hostname)
	assert.Contains(t, account.Groups["cfefqs706sqkneg59g3g"].Peers, addedPeer.ID)
	assert.Contains(t, account.Groups["cfefqs706sqkneg59g4g"].Peers, addedPeer.ID)

	assert.Equal(t, uint64(1), account.Network.Serial)

	lastLogin, err := time.Parse("2006-01-02T15:04:05Z", "0001-01-01T00:00:00Z")
	assert.NoError(t, err)
	assert.NotEqual(t, lastLogin, account.Users[existingUserID].GetLastLogin())
}

func Test_RegisterPeerBySetupKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	assert.NoError(t, err)

	am, err := BuildManager(context.Background(), s, NewPeersUpdateManager(nil), nil, "", "netbird.cloud", eventStore, nil, false, MocIntegratedValidator{}, metrics)
	assert.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	existingSetupKeyID := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	_, err = s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	newPeer := &nbpeer.Peer{
		ID:        xid.New().String(),
		AccountID: existingAccountID,
		Key:       "newPeerKey",
		UserID:    "",
		IP:        net.IP{123, 123, 123, 123},
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "newPeer",
			GoOS:     "linux",
		},
		Name:       "newPeerName",
		DNSLabel:   "newPeer.test",
		Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
		SSHEnabled: false,
	}

	addedPeer, _, _, err := am.AddPeer(context.Background(), existingSetupKeyID, "", newPeer)

	require.NoError(t, err)

	peer, err := s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthShare, newPeer.Key)
	require.NoError(t, err)
	assert.Equal(t, peer.AccountID, existingAccountID)

	account, err := s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)
	assert.Contains(t, account.Peers, addedPeer.ID)
	assert.Contains(t, account.Groups["cfefqs706sqkneg59g2g"].Peers, addedPeer.ID)
	assert.Contains(t, account.Groups["cfefqs706sqkneg59g4g"].Peers, addedPeer.ID)

	assert.Equal(t, uint64(1), account.Network.Serial)

	lastUsed, err := time.Parse("2006-01-02T15:04:05Z", "0001-01-01T00:00:00Z")
	assert.NoError(t, err)

	hashedKey := sha256.Sum256([]byte(existingSetupKeyID))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])
	assert.NotEqual(t, lastUsed, account.SetupKeys[encodedHashedKey].LastUsed)
	assert.Equal(t, 1, account.SetupKeys[encodedHashedKey].UsedTimes)

}

func Test_RegisterPeerRollbackOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	assert.NoError(t, err)

	am, err := BuildManager(context.Background(), s, NewPeersUpdateManager(nil), nil, "", "netbird.cloud", eventStore, nil, false, MocIntegratedValidator{}, metrics)
	assert.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	faultyKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBC"

	_, err = s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	newPeer := &nbpeer.Peer{
		ID:        xid.New().String(),
		AccountID: existingAccountID,
		Key:       "newPeerKey",
		UserID:    "",
		IP:        net.IP{123, 123, 123, 123},
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "newPeer",
			GoOS:     "linux",
		},
		Name:       "newPeerName",
		DNSLabel:   "newPeer.test",
		Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
		SSHEnabled: false,
	}

	_, _, _, err = am.AddPeer(context.Background(), faultyKey, "", newPeer)
	require.Error(t, err)

	_, err = s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthShare, newPeer.Key)
	require.Error(t, err)

	account, err := s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)
	assert.NotContains(t, account.Peers, newPeer.ID)
	assert.NotContains(t, account.Groups["cfefqs706sqkneg59g3g"].Peers, newPeer.ID)
	assert.NotContains(t, account.Groups["cfefqs706sqkneg59g4g"].Peers, newPeer.ID)

	assert.Equal(t, uint64(0), account.Network.Serial)

	lastUsed, err := time.Parse("2006-01-02T15:04:05Z", "0001-01-01T00:00:00Z")
	assert.NoError(t, err)

	hashedKey := sha256.Sum256([]byte(faultyKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])
	assert.Equal(t, lastUsed, account.SetupKeys[encodedHashedKey].GetLastUsed().UTC())
	assert.Equal(t, 0, account.SetupKeys[encodedHashedKey].UsedTimes)
}

func TestPeerAccountPeersUpdate(t *testing.T) {
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.DeletePolicy(context.Background(), account.Id, account.Policies[0].ID, userID)
	require.NoError(t, err)

	err = manager.SaveGroups(context.Background(), account.Id, userID, []*types.Group{
		{
			ID:    "groupA",
			Name:  "GroupA",
			Peers: []string{peer1.ID, peer2.ID, peer3.ID},
		},
		{
			ID:    "groupB",
			Name:  "GroupB",
			Peers: []string{},
		},
		{
			ID:    "groupC",
			Name:  "GroupC",
			Peers: []string{},
		},
	})
	require.NoError(t, err)

	// create a user with auto groups
	_, err = manager.SaveOrAddUsers(context.Background(), account.Id, userID, []*types.User{
		{
			Id:         "regularUser1",
			AccountID:  account.Id,
			Role:       types.UserRoleAdmin,
			Issued:     types.UserIssuedAPI,
			AutoGroups: []string{"groupA"},
		},
		{
			Id:         "regularUser2",
			AccountID:  account.Id,
			Role:       types.UserRoleAdmin,
			Issued:     types.UserIssuedAPI,
			AutoGroups: []string{"groupB"},
		},
		{
			Id:         "regularUser3",
			AccountID:  account.Id,
			Role:       types.UserRoleAdmin,
			Issued:     types.UserIssuedAPI,
			AutoGroups: []string{"groupC"},
		},
	}, true)
	require.NoError(t, err)

	var peer4 *nbpeer.Peer
	var peer5 *nbpeer.Peer
	var peer6 *nbpeer.Peer

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Updating not expired peer and peer expiration is enabled should not update account peers and not send peer update
	t.Run("updating not expired peer and peer expiration is enabled", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err := manager.UpdatePeer(context.Background(), account.Id, userID, peer2)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Adding peer to unlinked group should not update account peers and not send peer update
	t.Run("adding peer to unlinked group", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		expectedPeerKey := key.PublicKey().String()
		peer4, _, _, err = manager.AddPeer(context.Background(), "", "regularUser1", &nbpeer.Peer{
			Key:  expectedPeerKey,
			Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		})
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Deleting peer with unlinked group should not update account peers and not send peer update
	t.Run("deleting peer with unlinked group", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.DeletePeer(context.Background(), account.Id, peer4.ID, userID)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Updating peer label should update account peers and send peer update
	t.Run("updating peer label", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		peer1.Name = "peer-1"
		_, err = manager.UpdatePeer(context.Background(), account.Id, userID, peer1)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	t.Run("validator requires update", func(t *testing.T) {
		requireUpdateFunc := func(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *nbAccount.ExtraSettings) (*nbpeer.Peer, bool, error) {
			return update, true, nil
		}

		manager.integratedPeerValidator = MocIntegratedValidator{ValidatePeerFunc: requireUpdateFunc}
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.UpdatePeer(context.Background(), account.Id, userID, peer1)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	t.Run("validator requires no update", func(t *testing.T) {
		requireNoUpdateFunc := func(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *nbAccount.ExtraSettings) (*nbpeer.Peer, bool, error) {
			return update, false, nil
		}

		manager.integratedPeerValidator = MocIntegratedValidator{ValidatePeerFunc: requireNoUpdateFunc}
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.UpdatePeer(context.Background(), account.Id, userID, peer1)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Adding peer to group linked with policy should update account peers and send peer update
	t.Run("adding peer to group linked with policy", func(t *testing.T) {
		_, err = manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupA"},
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		})
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		expectedPeerKey := key.PublicKey().String()
		peer4, _, _, err = manager.AddPeer(context.Background(), "", "regularUser1", &nbpeer.Peer{
			Key:                    expectedPeerKey,
			LoginExpirationEnabled: true,
			Meta:                   nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		})
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting peer with linked group to policy should update account peers and send peer update
	t.Run("deleting peer with linked group to policy", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.DeletePeer(context.Background(), account.Id, peer4.ID, userID)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Adding peer to group linked with route should update account peers and send peer update
	t.Run("adding peer to group linked with route", func(t *testing.T) {
		route := nbroute.Route{
			ID:          "testingRoute1",
			Network:     netip.MustParsePrefix("100.65.250.202/32"),
			NetID:       "superNet",
			NetworkType: nbroute.IPv4Network,
			PeerGroups:  []string{"groupB"},
			Description: "super",
			Masquerade:  false,
			Metric:      9999,
			Enabled:     true,
			Groups:      []string{"groupB"},
		}

		_, err := manager.CreateRoute(
			context.Background(), account.Id, route.Network, route.NetworkType, route.Domains, route.Peer,
			route.PeerGroups, route.Description, route.NetID, route.Masquerade, route.Metric,
			route.Groups, []string{}, true, userID, route.KeepRoute,
		)
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		expectedPeerKey := key.PublicKey().String()
		peer5, _, _, err = manager.AddPeer(context.Background(), "", "regularUser2", &nbpeer.Peer{
			Key:                    expectedPeerKey,
			LoginExpirationEnabled: true,
			Meta:                   nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		})
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting peer with linked group to route should update account peers and send peer update
	t.Run("deleting peer with linked group to route", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.DeletePeer(context.Background(), account.Id, peer5.ID, userID)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Adding peer to group linked with name server group should update account peers and send peer update
	t.Run("adding peer to group linked with name server group", func(t *testing.T) {
		_, err = manager.CreateNameServerGroup(
			context.Background(), account.Id, "nsGroup", "nsGroup", []nbdns.NameServer{{
				IP:     netip.MustParseAddr("1.1.1.1"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			}},
			[]string{"groupC"},
			true, []string{}, true, userID, false,
		)
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		expectedPeerKey := key.PublicKey().String()
		peer6, _, _, err = manager.AddPeer(context.Background(), "", "regularUser3", &nbpeer.Peer{
			Key:                    expectedPeerKey,
			LoginExpirationEnabled: true,
			Meta:                   nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		})
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting peer with linked group to name server group should update account peers and send peer update
	t.Run("deleting peer with linked group to route", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.DeletePeer(context.Background(), account.Id, peer6.ID, userID)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}
