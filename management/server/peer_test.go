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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/shared/management/status"

	"github.com/netbirdio/netbird/management/server/util"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
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
	testGetNetworkMapGeneral(t)
}

func TestAccountManager_GetNetworkMap_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testGetNetworkMapGeneral(t)
}

func testGetNetworkMapGeneral(t *testing.T) {
	manager, _, err := createManager(t)
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

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userId, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	}, false)
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	_, _, _, err = manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	}, false)

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
	manager, _, err := createManager(t)
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

	peer1, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	}, false)
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	peer2, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	}, false)
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

	err = manager.CreateGroup(context.Background(), account.Id, userID, &group1)
	if err != nil {
		t.Errorf("expecting group1 to be added, got failure %v", err)
		return
	}
	err = manager.CreateGroup(context.Background(), account.Id, userID, &group2)
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
	policy, err = manager.SavePolicy(context.Background(), account.Id, userID, policy, true)
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
	_, err = manager.SavePolicy(context.Background(), account.Id, userID, policy, true)
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
	manager, _, err := createManager(t)
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

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userId, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	}, false)
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	peerKey2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	_, _, _, err = manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	}, false)

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
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	// account with an admin and a regular user
	accountID := "test_account"
	adminUser := "account_creator"
	someUser := "some_user"
	account := newAccountWithId(context.Background(), accountID, adminUser, "", "", "", false)
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
	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, adminUser, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, _, err := manager.AddPeer(context.Background(), "", "", someUser, &nbpeer.Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	}, false)
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
	peer2, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	}, false)
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
			manager, _, err := createManager(t)
			if err != nil {
				t.Fatal(err)
				return
			}

			// account with an admin and a regular user
			accountID := "test_account"
			adminUser := "account_creator"
			someUser := "some_user"
			account := newAccountWithId(context.Background(), accountID, adminUser, "", "", "", false)
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

			_, _, _, err = manager.AddPeer(context.Background(), "", "", someUser, &nbpeer.Peer{
				Key:  peerKey1.PublicKey().String(),
				Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
			}, false)
			if err != nil {
				t.Errorf("expecting peer to be added, got failure %v", err)
				return
			}

			_, _, _, err = manager.AddPeer(context.Background(), "", "", adminUser, &nbpeer.Peer{
				Key:  peerKey2.PublicKey().String(),
				Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
			}, false)
			if err != nil {
				t.Errorf("expecting peer to be added, got failure %v", err)
				return
			}

			peers, err := manager.GetPeers(context.Background(), accountID, someUser, "", "")
			if err != nil {
				t.Fatal(err)
				return
			}
			assert.NotNil(t, peers)

			assert.Len(t, peers, testCase.expectedPeerCount)

		})
	}
}

func setupTestAccountManager(b testing.TB, peers int, groups int) (*DefaultAccountManager, *update_channel.PeersUpdateManager, string, string, error) {
	b.Helper()

	manager, updateManager, err := createManager(b)
	if err != nil {
		return nil, nil, "", "", err
	}

	accountID := "test_account"
	adminUser := "account_creator"
	regularUser := "regular_user"

	account := newAccountWithId(context.Background(), accountID, adminUser, "", "", "", false)
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
			return nil, nil, "", "", err
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
		return nil, nil, "", "", err
	}

	return manager, updateManager, accountID, regularUser, nil
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
			manager, _, accountID, userID, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := manager.GetPeers(context.Background(), accountID, userID, "", "")
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
		{"Extra Large", 2000, 2000, 1300, 2400, 3000, 6400},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}

			ctx := context.Background()

			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}

			for peerID := range account.Peers {
				updateManager.CreateChannel(ctx, peerID)
			}

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				manager.UpdateAccountPeers(ctx, account.Id)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				maxExpected = bc.maxMsPerOpCICD
				testing_tools.EvaluateBenchmarkResults(b, bc.name, time.Since(start), "login", "newPeer")
			}

			if msPerOp > maxExpected {
				b.Logf("Benchmark %s: too slow (%.2f ms/op, max %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func TestUpdateAccountPeers_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testUpdateAccountPeers(t)
}

func TestUpdateAccountPeers(t *testing.T) {
	testUpdateAccountPeers(t)
}

func testUpdateAccountPeers(t *testing.T) {
	testCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Small", 50, 1},
		{"Medium", 500, 1},
		{"Large", 1000, 1},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(t, tc.peers, tc.groups)
			if err != nil {
				t.Fatalf("Failed to setup test account manager: %v", err)
			}

			ctx := context.Background()

			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				t.Fatalf("Failed to get account: %v", err)
			}

			peerChannels := make(map[string]chan *network_map.UpdateMessage)

			for peerID := range account.Peers {
				peerChannels[peerID] = updateManager.CreateChannel(ctx, peerID)
			}

			manager.UpdateAccountPeers(ctx, account.Id)

			for _, channel := range peerChannels {
				update := <-channel
				assert.Nil(t, update.Update.NetbirdConfig)
				assert.Equal(t, tc.peers, len(update.Update.NetworkMap.RemotePeers))
				assert.Equal(t, tc.peers*2, len(update.Update.NetworkMap.FirewallRules))
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

	config := &config.Config{
		Signal: &config.Host{
			Proto:    "https",
			URI:      "signal.uri",
			Username: "",
			Password: "",
		},
		Stuns: []*config.Host{{URI: "stun.uri", Proto: config.UDP}},
		TURNConfig: &config.TURNConfig{
			Turns: []*config.Host{{URI: "turn.uri", Proto: config.UDP, Username: "turn-user", Password: "turn-pass"}},
		},
	}
	peer := &nbpeer.Peer{
		IP:         net.ParseIP("192.168.1.1"),
		SSHEnabled: true,
		Key:        "peer-key",
		DNSLabel:   "peer1",
		SSHKey:     "peer1-ssh-key",
	}
	turnRelayToken := &grpc.Token{
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
		ForwardingRules: []*types.ForwardingRule{
			{
				RuleProtocol: "tcp",
				DestinationPorts: types.RulePortRange{
					Start: 1000,
					End:   2000,
				},
				TranslatedAddress: net.IPv4(192, 168, 1, 2),
				TranslatedPorts: types.RulePortRange{
					Start: 11000,
					End:   12000,
				},
			},
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
	dnsCache := &cache.DNSConfigCache{}
	accountSettings := &types.Settings{RoutingPeerDNSResolutionEnabled: true}
	response := grpc.ToSyncResponse(context.Background(), config, config.HttpConfig, config.DeviceAuthorizationFlow, peer, turnRelayToken, turnRelayToken, networkMap, dnsName, checks, dnsCache, accountSettings, nil, []string{}, int64(dnsForwarderPort))

	assert.NotNil(t, response)
	// assert peer config
	assert.Equal(t, "192.168.1.1/24", response.PeerConfig.Address)
	assert.Equal(t, "peer1.example.com", response.PeerConfig.Fqdn)
	assert.Equal(t, true, response.PeerConfig.SshConfig.SshEnabled)
	// assert netbird config
	assert.Equal(t, "signal.uri", response.NetbirdConfig.Signal.Uri)
	assert.Equal(t, proto.HostConfig_HTTPS, response.NetbirdConfig.Signal.GetProtocol())
	assert.Equal(t, "stun.uri", response.NetbirdConfig.Stuns[0].Uri)
	assert.Equal(t, "turn.uri", response.NetbirdConfig.Turns[0].HostConfig.GetUri())
	assert.Equal(t, "turn-user", response.NetbirdConfig.Turns[0].User)
	assert.Equal(t, "turn-pass", response.NetbirdConfig.Turns[0].Password)
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
	//nolint
	assert.Equal(t, int64(dnsForwarderPort), response.NetworkMap.DNSConfig.ForwarderPort)
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
	// assert network map ForwardingRules
	assert.Equal(t, 1, len(response.NetworkMap.ForwardingRules))
	assert.Equal(t, proto.RuleProtocol_TCP, response.NetworkMap.ForwardingRules[0].Protocol)
	assert.Equal(t, uint32(1000), response.NetworkMap.ForwardingRules[0].DestinationPort.GetRange().Start)
	assert.Equal(t, uint32(2000), response.NetworkMap.ForwardingRules[0].DestinationPort.GetRange().End)
	assert.Equal(t, net.IPv4(192, 168, 1, 2).To4(), net.IP(response.NetworkMap.ForwardingRules[0].TranslatedAddress))
	assert.Equal(t, uint32(11000), response.NetworkMap.ForwardingRules[0].TranslatedPort.GetRange().Start)
	assert.Equal(t, uint32(12000), response.NetworkMap.ForwardingRules[0].TranslatedPort.GetRange().End)
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

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	permissionsManager := permissions.NewManager(s)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, s)
	networkMapController := controller.NewController(ctx, s, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(s, peers.NewManager(s, permissionsManager)), &config.Config{})

	am, err := BuildManager(context.Background(), nil, s, networkMapController, nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
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
		ExtraDNSLabels: []string{
			"extraLabel1",
			"extraLabel2",
		},
	}

	addedPeer, _, _, err := am.AddPeer(context.Background(), "", "", existingUserID, newPeer, false)
	require.NoError(t, err)
	assert.Equal(t, newPeer.ExtraDNSLabels, addedPeer.ExtraDNSLabels)

	peer, err := s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, addedPeer.Key)
	require.NoError(t, err)
	assert.Equal(t, peer.AccountID, existingAccountID)
	assert.Equal(t, peer.UserID, existingUserID)
	assert.Equal(t, newPeer.ExtraDNSLabels, peer.ExtraDNSLabels)

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

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.
		EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()
	permissionsManager := permissions.NewManager(s)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, s)
	networkMapController := controller.NewController(ctx, s, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(s, peers.NewManager(s, permissionsManager)), &config.Config{})

	am, err := BuildManager(context.Background(), nil, s, networkMapController, nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
	assert.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	newPeerTemplate := &nbpeer.Peer{
		AccountID: existingAccountID,
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
		ExtraDNSLabels: []string{
			"extraLabel1",
			"extraLabel2",
		},
	}

	testCases := []struct {
		name                      string
		existingSetupKeyID        string
		expectedGroupIDsInAccount []string
		expectAddPeerError        bool
		errorType                 status.Type
		expectedErrorMsgSubstring string
	}{
		{
			name:                      "Successful registration with setup key allowing extra DNS labels",
			existingSetupKeyID:        "A2C8E62B-38F5-4553-B31E-DD66C696CEBD",
			expectAddPeerError:        false,
			expectedGroupIDsInAccount: []string{"cfefqs706sqkneg59g2g", "cfefqs706sqkneg59g4g"},
		},
		{
			name:                      "Failed registration with setup key not allowing extra DNS labels",
			existingSetupKeyID:        "A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
			expectAddPeerError:        true,
			errorType:                 status.PreconditionFailed,
			expectedErrorMsgSubstring: "setup key doesn't allow extra DNS labels",
		},
		{
			name:                      "Absent setup key",
			existingSetupKeyID:        "AAAAAAAA-38F5-4553-B31E-DD66C696CEBB",
			expectAddPeerError:        true,
			errorType:                 status.NotFound,
			expectedErrorMsgSubstring: "couldn't add peer: setup key is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentPeer := &nbpeer.Peer{
				ID:             xid.New().String(),
				AccountID:      newPeerTemplate.AccountID,
				Key:            "newPeerKey_" + xid.New().String(),
				UserID:         newPeerTemplate.UserID,
				IP:             newPeerTemplate.IP,
				Meta:           newPeerTemplate.Meta,
				Name:           newPeerTemplate.Name,
				DNSLabel:       newPeerTemplate.DNSLabel,
				Status:         &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
				SSHEnabled:     newPeerTemplate.SSHEnabled,
				ExtraDNSLabels: newPeerTemplate.ExtraDNSLabels,
			}

			addedPeer, _, _, err := am.AddPeer(context.Background(), "", tc.existingSetupKeyID, "", currentPeer, false)

			if tc.expectAddPeerError {
				require.Error(t, err, "Expected an error when adding peer with setup key: %s", tc.existingSetupKeyID)
				assert.Contains(t, err.Error(), tc.expectedErrorMsgSubstring, "Error message mismatch")
				e, ok := status.FromError(err)
				if !ok {
					t.Fatal("Failed to map error")
				}
				assert.Equal(t, e.Type(), tc.errorType)
				return
			}

			require.NoError(t, err, "Expected no error when adding peer with setup key: %s", tc.existingSetupKeyID)
			assert.NotNil(t, addedPeer, "addedPeer should not be nil on success")
			assert.Equal(t, currentPeer.ExtraDNSLabels, addedPeer.ExtraDNSLabels, "ExtraDNSLabels mismatch")

			peerFromStore, err := s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, currentPeer.Key)
			require.NoError(t, err, "Failed to get peer by pub key: %s", currentPeer.Key)
			assert.Equal(t, existingAccountID, peerFromStore.AccountID, "AccountID mismatch for peer from store")
			assert.Equal(t, currentPeer.ExtraDNSLabels, peerFromStore.ExtraDNSLabels, "ExtraDNSLabels mismatch for peer from store")
			assert.Equal(t, addedPeer.ID, peerFromStore.ID, "Peer ID mismatch between addedPeer and peerFromStore")

			account, err := s.GetAccount(context.Background(), existingAccountID)
			require.NoError(t, err, "Failed to get account: %s", existingAccountID)
			assert.Contains(t, account.Peers, addedPeer.ID, "Peer ID not found in account.Peers")

			for _, groupID := range tc.expectedGroupIDsInAccount {
				require.NotNil(t, account.Groups[groupID], "Group %s not found in account", groupID)
				assert.Contains(t, account.Groups[groupID].Peers, addedPeer.ID, "Peer ID %s not found in group %s", addedPeer.ID, groupID)
			}

			assert.Equal(t, uint64(1), account.Network.Serial, "Network.Serial mismatch; this assumes specific initial state or increment logic.")

			hashedKey := sha256.Sum256([]byte(tc.existingSetupKeyID))
			encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

			setupKeyData, ok := account.SetupKeys[encodedHashedKey]
			require.True(t, ok, "Setup key data not found in account.SetupKeys for key ID %s (encoded: %s)", tc.existingSetupKeyID, encodedHashedKey)

			var zeroTime time.Time
			assert.NotEqual(t, zeroTime, setupKeyData.LastUsed, "Setup key LastUsed time should have been updated and not be zero.")

			assert.Equal(t, 1, setupKeyData.UsedTimes, "Setup key UsedTimes should be 1 after first use.")
		})
	}

}

func Test_RegisterPeerRollbackOnFailure(t *testing.T) {
	engine := os.Getenv("NETBIRD_STORE_ENGINE")
	if engine == "sqlite" || engine == "mysql" || engine == "" {
		// we intentionally disabled foreign keys in mysql
		t.Skip("Skipping test because store is not respecting foreign keys")
	}
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

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)

	permissionsManager := permissions.NewManager(s)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, s)
	networkMapController := controller.NewController(ctx, s, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(s, peers.NewManager(s, permissionsManager)), &config.Config{})

	am, err := BuildManager(context.Background(), nil, s, networkMapController, nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
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

	_, _, _, err = am.AddPeer(context.Background(), "", faultyKey, "", newPeer, false)
	require.Error(t, err)

	_, err = s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, newPeer.Key)
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

func Test_LoginPeer(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
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

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.
		EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()
	permissionsManager := permissions.NewManager(s)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, s)
	networkMapController := controller.NewController(ctx, s, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(s, peers.NewManager(s, permissionsManager)), &config.Config{})

	am, err := BuildManager(context.Background(), nil, s, networkMapController, nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
	assert.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	_, err = s.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err, "Failed to get existing account, check testdata/extended-store.sql. Account ID: %s", existingAccountID)

	baseMeta := nbpeer.PeerSystemMeta{
		Hostname: "loginPeerHost",
		GoOS:     "linux",
	}

	newPeerTemplate := &nbpeer.Peer{
		AccountID: existingAccountID,
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
		ExtraDNSLabels: []string{
			"extraLabel1",
			"extraLabel2",
		},
	}

	testCases := []struct {
		name                         string
		setupKey                     string
		expectExtraDNSLabelsMismatch bool
		extraDNSLabels               []string
		expectLoginError             bool
		expectedErrorMsgSubstring    string
	}{
		{
			name:             "Successful login with setup key",
			setupKey:         "A2C8E62B-38F5-4553-B31E-DD66C696CEBD",
			expectLoginError: false,
		},
		{
			name:                         "Successful login with setup key with DNS labels mismatch",
			setupKey:                     "A2C8E62B-38F5-4553-B31E-DD66C696CEBD",
			expectExtraDNSLabelsMismatch: true,
			extraDNSLabels:               []string{"anotherLabel1", "anotherLabel2"},
			expectLoginError:             false,
		},
		{
			name:                         "Failed login with setup key not allowing extra DNS labels",
			setupKey:                     "A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
			expectExtraDNSLabelsMismatch: true,
			extraDNSLabels:               []string{"anotherLabel1", "anotherLabel2"},
			expectLoginError:             true,
			expectedErrorMsgSubstring:    "setup key doesn't allow extra DNS labels",
		},
	}

	for _, tc := range testCases {
		currentWireGuardPubKey := "testPubKey_" + xid.New().String()

		t.Run(tc.name, func(t *testing.T) {
			upperKey := strings.ToUpper(tc.setupKey)
			hashedKey := sha256.Sum256([]byte(upperKey))
			encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])
			sk, err := s.GetSetupKeyBySecret(context.Background(), store.LockingStrengthUpdate, encodedHashedKey)
			require.NoError(t, err, "Failed to get setup key %s from storage", tc.setupKey)

			currentPeer := &nbpeer.Peer{
				ID:         xid.New().String(),
				AccountID:  newPeerTemplate.AccountID,
				Key:        currentWireGuardPubKey,
				UserID:     newPeerTemplate.UserID,
				IP:         newPeerTemplate.IP,
				Meta:       newPeerTemplate.Meta,
				Name:       newPeerTemplate.Name,
				DNSLabel:   newPeerTemplate.DNSLabel,
				Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
				SSHEnabled: newPeerTemplate.SSHEnabled,
			}
			// add peer manually to bypass creation during login stage
			if sk.AllowExtraDNSLabels {
				currentPeer.ExtraDNSLabels = newPeerTemplate.ExtraDNSLabels
			}
			_, _, _, err = am.AddPeer(context.Background(), "", tc.setupKey, "", currentPeer, false)
			require.NoError(t, err, "Expected no error when adding peer with setup key: %s", tc.setupKey)

			loginInput := types.PeerLogin{
				WireGuardPubKey: currentWireGuardPubKey,
				SSHKey:          "test-ssh-key",
				Meta:            baseMeta,
				UserID:          "",
				SetupKey:        tc.setupKey,
				ConnectionIP:    net.ParseIP("192.0.2.100"),
			}

			if tc.expectExtraDNSLabelsMismatch {
				loginInput.ExtraDNSLabels = tc.extraDNSLabels
			}

			loggedinPeer, networkMap, postureChecks, loginErr := am.LoginPeer(context.Background(), loginInput)
			if tc.expectLoginError {
				require.Error(t, loginErr, "Expected an error during LoginPeer with setup key: %s", tc.setupKey)
				assert.Contains(t, loginErr.Error(), tc.expectedErrorMsgSubstring, "Error message mismatch")
				assert.Nil(t, loggedinPeer, "LoggedinPeer should be nil on error")
				assert.Nil(t, networkMap, "NetworkMap should be nil on error")
				assert.Nil(t, postureChecks, "PostureChecks should be empty or nil on error")
				return
			}

			require.NoError(t, loginErr, "Expected no error during LoginPeer with setup key: %s", tc.setupKey)
			assert.NotNil(t, loggedinPeer, "loggedinPeer should not be nil on success")
			if tc.expectExtraDNSLabelsMismatch {
				assert.NotEqual(t, tc.extraDNSLabels, loggedinPeer.ExtraDNSLabels, "ExtraDNSLabels should not match on loggedinPeer")
				assert.Equal(t, currentPeer.ExtraDNSLabels, loggedinPeer.ExtraDNSLabels, "ExtraDNSLabels mismatch on loggedinPeer")
			} else {
				assert.Equal(t, currentPeer.ExtraDNSLabels, loggedinPeer.ExtraDNSLabels, "ExtraDNSLabels mismatch on loggedinPeer")
			}
			assert.NotNil(t, networkMap, "networkMap should not be nil on success")

			assert.Equal(t, existingAccountID, loggedinPeer.AccountID, "AccountID mismatch for logged peer")

			peerFromStore, err := s.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, loginInput.WireGuardPubKey)
			require.NoError(t, err, "Failed to get peer by pub key: %s", loginInput.WireGuardPubKey)
			assert.Equal(t, existingAccountID, peerFromStore.AccountID, "AccountID mismatch for peer from store")
			assert.Equal(t, loggedinPeer.ID, peerFromStore.ID, "Peer ID mismatch between loggedinPeer and peerFromStore")
		})
	}
}

func TestPeerAccountPeersUpdate(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.DeletePolicy(context.Background(), account.Id, account.Policies[0].ID, userID)
	require.NoError(t, err)

	g := []*types.Group{
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
	}
	for _, group := range g {
		err = manager.CreateGroup(context.Background(), account.Id, userID, group)
		require.NoError(t, err)
	}

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

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Updating not expired peer and peer expiration is enabled should not update account peers and not send peer update
	t.Run("updating not expired peer and peer expiration is enabled", func(t *testing.T) {
		t.Skip("Currently all updates will trigger a network map")
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
			peerShouldReceiveUpdate(t, updMsg) //
			close(done)
		}()

		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		expectedPeerKey := key.PublicKey().String()
		peer4, _, _, err = manager.AddPeer(context.Background(), "", "", "regularUser1", &nbpeer.Peer{
			Key:  expectedPeerKey,
			Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		}, false)
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
			peerShouldReceiveUpdate(t, updMsg)
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
		requireUpdateFunc := func(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
			return update, true, nil
		}

		manager.integratedPeerValidator = MockIntegratedValidator{ValidatePeerFunc: requireUpdateFunc}
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
		t.Skip("Currently all updates will trigger a network map")

		requireNoUpdateFunc := func(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
			return update, false, nil
		}

		manager.integratedPeerValidator = MockIntegratedValidator{ValidatePeerFunc: requireNoUpdateFunc}
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
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"groupA"},
					Destinations:  []string{"groupA"},
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		expectedPeerKey := key.PublicKey().String()
		peer4, _, _, err = manager.AddPeer(context.Background(), "", "", "regularUser1", &nbpeer.Peer{
			Key:                    expectedPeerKey,
			LoginExpirationEnabled: true,
			Meta:                   nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		}, false)
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
			route.Groups, []string{}, true, userID, route.KeepRoute, route.SkipAutoApply,
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
		peer5, _, _, err = manager.AddPeer(context.Background(), "", "", "regularUser2", &nbpeer.Peer{
			Key:                    expectedPeerKey,
			LoginExpirationEnabled: true,
			Meta:                   nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		}, false)
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
		peer6, _, _, err = manager.AddPeer(context.Background(), "", "", "regularUser3", &nbpeer.Peer{
			Key:                    expectedPeerKey,
			LoginExpirationEnabled: true,
			Meta:                   nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		}, false)
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

func Test_DeletePeer(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	// account with an admin and a regular user
	accountID := "test_account"
	adminUser := "account_creator"
	account := newAccountWithId(context.Background(), accountID, adminUser, "", "", "", false)
	account.Peers = map[string]*nbpeer.Peer{
		"peer1": {
			ID:        "peer1",
			AccountID: accountID,
			Key:       "key1",
			IP:        net.IP{1, 1, 1, 1},
			DNSLabel:  "peer1.test",
		},
		"peer2": {
			ID:        "peer2",
			AccountID: accountID,
			Key:       "key2",
			IP:        net.IP{2, 2, 2, 2},
			DNSLabel:  "peer2.test",
		},
	}
	account.Groups = map[string]*types.Group{
		"group1": {
			ID:    "group1",
			Name:  "Group1",
			Peers: []string{"peer1", "peer2"},
		},
	}

	err = manager.Store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatal(err)
		return
	}

	err = manager.DeletePeer(context.Background(), accountID, "peer1", adminUser)
	if err != nil {
		t.Fatalf("DeletePeer failed: %v", err)
	}

	_, err = manager.GetPeer(context.Background(), accountID, "peer1", adminUser)
	assert.Error(t, err)

	group, err := manager.GetGroup(context.Background(), accountID, "group1", adminUser)
	assert.NoError(t, err)
	assert.NotContains(t, group.Peers, "peer1")

}

func Test_IsUniqueConstraintError(t *testing.T) {
	tests := []struct {
		name   string
		engine types.Engine
	}{
		{
			name:   "PostgreSQL uniqueness error",
			engine: types.PostgresStoreEngine,
		},
		{
			name:   "MySQL uniqueness error",
			engine: types.MysqlStoreEngine,
		},
		{
			name:   "SQLite uniqueness error",
			engine: types.SqliteStoreEngine,
		},
	}

	peer := &nbpeer.Peer{
		ID:        "test-peer-id",
		AccountID: "bf1c8084-ba50-4ce7-9439-34653001fc3b",
		DNSLabel:  "test-peer-dns-label",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NETBIRD_STORE_ENGINE", string(tt.engine))
			s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
			if err != nil {
				t.Fatalf("Error when creating store: %s", err)
			}
			t.Cleanup(cleanup)

			err = s.AddPeerToAccount(context.Background(), peer)
			assert.NoError(t, err)

			err = s.AddPeerToAccount(context.Background(), peer)
			result := isUniqueConstraintError(err)
			assert.True(t, result)
		})
	}
}

func Test_AddPeer(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	accountID := "testaccount"
	userID := "testuser"

	_, err = createAccount(manager, accountID, userID, "domain.com")
	if err != nil {
		t.Fatalf("error creating account: %v", err)
		return
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), accountID, "test-key", types.SetupKeyReusable, time.Hour, nil, 10000, userID, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	const totalPeers = 300

	var wg sync.WaitGroup
	errs := make(chan error, totalPeers)
	start := make(chan struct{})
	for i := 0; i < totalPeers; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			newPeer := &nbpeer.Peer{
				AccountID: accountID,
				Key:       "key" + strconv.Itoa(i),
				Meta:      nbpeer.PeerSystemMeta{Hostname: "peer" + strconv.Itoa(i), GoOS: "linux"},
			}

			<-start

			_, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", newPeer, false)
			if err != nil {
				errs <- fmt.Errorf("AddPeer failed for peer %d: %w", i, err)
				return
			}

		}(i)
	}
	startTime := time.Now()

	close(start)
	wg.Wait()
	close(errs)

	t.Logf("time since start: %s", time.Since(startTime))

	for err := range errs {
		t.Fatal(err)
	}

	account, err := manager.Store.GetAccount(context.Background(), accountID)
	if err != nil {
		t.Fatalf("Failed to get account %s: %v", accountID, err)
	}

	assert.Equal(t, totalPeers, len(account.Peers), "Expected %d peers in account %s, got %d", totalPeers, accountID, len(account.Peers))

	seenIP := make(map[string]bool)
	for _, p := range account.Peers {
		ipStr := p.IP.String()
		if seenIP[ipStr] {
			t.Fatalf("Duplicate IP found in account %s: %s", accountID, ipStr)
		}
		seenIP[ipStr] = true
	}

	seenLabel := make(map[string]bool)
	for _, p := range account.Peers {
		if seenLabel[p.DNSLabel] {
			t.Fatalf("Duplicate Label found in account %s: %s", accountID, p.DNSLabel)
		}
		seenLabel[p.DNSLabel] = true
	}

	assert.Equal(t, totalPeers, maps.Values(account.SetupKeys)[0].UsedTimes)
	assert.Equal(t, uint64(totalPeers), account.Network.Serial)
}

func TestAddPeer_UserPendingApprovalBlocked(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create account
	account := newAccountWithId(context.Background(), "test-account", "owner", "", "", "", false)
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Create user pending approval
	pendingUser := types.NewRegularUser("pending-user", "", "")
	pendingUser.AccountID = account.Id
	pendingUser.Blocked = true
	pendingUser.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser)
	require.NoError(t, err)

	// Try to add peer with pending approval user
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	peer := &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Name: "test-peer",
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "test-peer",
			OS:       "linux",
		},
	}

	_, _, _, err = manager.AddPeer(context.Background(), "", "", pendingUser.Id, peer, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user pending approval cannot add peers")
}

func TestAddPeer_ApprovedUserCanAddPeers(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create account
	account := newAccountWithId(context.Background(), "test-account", "owner", "", "", "", false)
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Create regular user (not pending approval)
	regularUser := types.NewRegularUser("regular-user", "", "")
	regularUser.AccountID = account.Id
	err = manager.Store.SaveUser(context.Background(), regularUser)
	require.NoError(t, err)

	// Try to add peer with regular user
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	peer := &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Name: "test-peer",
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "test-peer",
			OS:       "linux",
		},
	}

	_, _, _, err = manager.AddPeer(context.Background(), "", "", regularUser.Id, peer, false)
	require.NoError(t, err, "Regular user should be able to add peers")
}

func TestLoginPeer_UserPendingApprovalBlocked(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create account
	account := newAccountWithId(context.Background(), "test-account", "owner", "", "", "", false)
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Create user pending approval
	pendingUser := types.NewRegularUser("pending-user", "", "")
	pendingUser.AccountID = account.Id
	pendingUser.Blocked = true
	pendingUser.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser)
	require.NoError(t, err)

	// Create a peer using AddPeer method for the pending user (simulate existing peer)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	// Set the user to not be pending initially so peer can be added
	pendingUser.Blocked = false
	pendingUser.PendingApproval = false
	err = manager.Store.SaveUser(context.Background(), pendingUser)
	require.NoError(t, err)

	// Add peer using regular flow
	newPeer := &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Name: "test-peer",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-peer",
			OS:        "linux",
			WtVersion: "0.28.0",
		},
	}
	existingPeer, _, _, err := manager.AddPeer(context.Background(), "", "", pendingUser.Id, newPeer, false)
	require.NoError(t, err)

	// Now set the user back to pending approval after peer was created
	pendingUser.Blocked = true
	pendingUser.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser)
	require.NoError(t, err)

	// Try to login with pending approval user
	login := types.PeerLogin{
		WireGuardPubKey: existingPeer.Key,
		UserID:          pendingUser.Id,
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "test-peer",
			OS:       "linux",
		},
	}

	_, _, _, err = manager.LoginPeer(context.Background(), login)
	require.Error(t, err)
	e, ok := status.FromError(err)
	require.True(t, ok, "error is not a gRPC status error")
	assert.Equal(t, status.PermissionDenied, e.Type(), "expected PermissionDenied error code")
}

func TestLoginPeer_ApprovedUserCanLogin(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create account
	account := newAccountWithId(context.Background(), "test-account", "owner", "", "", "", false)
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Create regular user (not pending approval)
	regularUser := types.NewRegularUser("regular-user", "", "")
	regularUser.AccountID = account.Id
	err = manager.Store.SaveUser(context.Background(), regularUser)
	require.NoError(t, err)

	// Add peer using regular flow for the regular user
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	newPeer := &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Name: "test-peer",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-peer",
			OS:        "linux",
			WtVersion: "0.28.0",
		},
	}
	existingPeer, _, _, err := manager.AddPeer(context.Background(), "", "", regularUser.Id, newPeer, false)
	require.NoError(t, err)

	// Try to login with regular user
	login := types.PeerLogin{
		WireGuardPubKey: existingPeer.Key,
		UserID:          regularUser.Id,
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "test-peer",
			OS:       "linux",
		},
	}

	_, _, _, err = manager.LoginPeer(context.Background(), login)
	require.NoError(t, err, "Regular user should be able to login peers")
}
