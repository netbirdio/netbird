package server

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	"github.com/rs/xid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeer_LoginExpired(t *testing.T) {

	tt := []struct {
		name              string
		expirationEnabled bool
		lastLogin         time.Time
		expected          bool
		accountSettings   *Settings
	}{
		{
			name:              "Peer Login Expiration Disabled. Peer Login Should Not Expire",
			expirationEnabled: false,
			lastLogin:         time.Now().Add(-25 * time.Hour),
			accountSettings: &Settings{
				PeerLoginExpirationEnabled: true,
				PeerLoginExpiration:        time.Hour,
			},
			expected: false,
		},
		{
			name:              "Peer Login Should Expire",
			expirationEnabled: true,
			lastLogin:         time.Now().Add(-25 * time.Hour),
			accountSettings: &Settings{
				PeerLoginExpirationEnabled: true,
				PeerLoginExpiration:        time.Hour,
			},
			expected: true,
		},
		{
			name:              "Peer Login Should Not Expire",
			expirationEnabled: true,
			lastLogin:         time.Now(),
			accountSettings: &Settings{
				PeerLoginExpirationEnabled: true,
				PeerLoginExpiration:        time.Hour,
			},
			expected: false,
		},
	}

	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			peer := &Peer{
				LoginExpirationEnabled: c.expirationEnabled,
				LastLogin:              c.lastLogin,
				UserID:                 userID,
			}

			expired, _ := peer.LoginExpired(c.accountSettings.PeerLoginExpiration)
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

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		if key.Type == SetupKeyReusable {
			setupKey = key
		}
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-1"},
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
	_, _, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-2"},
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	networkMap, err := manager.GetNetworkMap(peer1.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap.Peers) != 1 {
		t.Errorf("expecting Account NetworkMap to have 1 peers, got %v", len(networkMap.Peers))
	}

	if networkMap.Peers[0].Key != peerKey2.PublicKey().String() {
		t.Errorf(
			"expecting Account NetworkMap to have peer with a key %s, got %s",
			peerKey2.PublicKey().String(),
			networkMap.Peers[0].Key,
		)
	}
}

func TestAccountManager_GetNetworkMapWithRule(t *testing.T) {
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

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		if key.Type == SetupKeyReusable {
			setupKey = key
		}
	}

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-1"},
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
	peer2, _, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-2"},
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	rules, err := manager.ListRules(account.Id, userID)
	if err != nil {
		t.Errorf("expecting to get a list of rules, got failure %v", err)
		return
	}

	err = manager.DeleteRule(account.Id, rules[0].ID, userID)
	if err != nil {
		t.Errorf("expecting to delete 1 group, got failure %v", err)
		return
	}
	var (
		group1 Group
		group2 Group
		rule   Rule
	)

	group1.ID = xid.New().String()
	group2.ID = xid.New().String()
	group1.Name = "src"
	group2.Name = "dst"
	rule.ID = xid.New().String()
	group1.Peers = append(group1.Peers, peer1.ID)
	group2.Peers = append(group2.Peers, peer2.ID)

	err = manager.SaveGroup(account.Id, userID, &group1)
	if err != nil {
		t.Errorf("expecting group1 to be added, got failure %v", err)
		return
	}
	err = manager.SaveGroup(account.Id, userID, &group2)
	if err != nil {
		t.Errorf("expecting group2 to be added, got failure %v", err)
		return
	}

	rule.Name = "test"
	rule.Source = append(rule.Source, group1.ID)
	rule.Destination = append(rule.Destination, group2.ID)
	rule.Flow = TrafficFlowBidirect
	err = manager.SaveRule(account.Id, userID, &rule)
	if err != nil {
		t.Errorf("expecting rule to be added, got failure %v", err)
		return
	}

	networkMap1, err := manager.GetNetworkMap(peer1.ID)
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

	networkMap2, err := manager.GetNetworkMap(peer2.ID)
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

	rule.Disabled = true
	err = manager.SaveRule(account.Id, userID, &rule)
	if err != nil {
		t.Errorf("expecting rule to be added, got failure %v", err)
		return
	}

	networkMap1, err = manager.GetNetworkMap(peer1.ID)
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

	networkMap2, err = manager.GetNetworkMap(peer2.ID)
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

	setupKey := getSetupKey(account, SetupKeyReusable)

	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-1"},
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
	_, _, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-2"},
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	network, err := manager.GetPeerNetwork(peer1.ID)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Network.Id != network.Id {
		t.Errorf("expecting Account Networks ID to be equal, got %s expected %s", network.Id, account.Network.Id)
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
	account := newAccountWithId(accountID, adminUser, "")
	account.Users[someUser] = &User{
		Id:   someUser,
		Role: UserRoleUser,
	}
	err = manager.Store.SaveAccount(account)
	if err != nil {
		t.Fatal(err)
		return
	}

	// two peers one added by a regular user and one with a setup key
	setupKey := getSetupKey(account, SetupKeyReusable)
	peerKey1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1, _, err := manager.AddPeer("", someUser, &Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-2"},
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
	peer2, _, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: PeerSystemMeta{Hostname: "test-peer-2"},
	})

	if err != nil {
		t.Fatal(err)
		return
	}

	// the user can see its own peer
	peer, err := manager.GetPeer(accountID, peer1.ID, someUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

	// the user can see peer2 because peer1 of the user has access to peer2 due to the All group and the default rule 0 all-to-all access
	peer, err = manager.GetPeer(accountID, peer2.ID, someUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

	// delete the all-to-all rule so that user's peer1 has no access to peer2
	for _, rule := range account.Rules {
		err = manager.DeleteRule(accountID, rule.ID, adminUser)
		if err != nil {
			t.Fatal(err)
			return
		}
	}

	// at this point the user can't see the details of peer2
	peer, err = manager.GetPeer(accountID, peer2.ID, someUser) //nolint
	assert.Error(t, err)

	// admin users can always access all the peers
	peer, err = manager.GetPeer(accountID, peer1.ID, adminUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

	peer, err = manager.GetPeer(accountID, peer2.ID, adminUser)
	if err != nil {
		t.Fatal(err)
		return
	}
	assert.NotNil(t, peer)

}

func getSetupKey(account *Account, keyType SetupKeyType) *SetupKey {

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		if key.Type == keyType {
			setupKey = key
		}
	}
	return setupKey
}
