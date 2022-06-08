package server

import (
	"testing"

	"github.com/rs/xid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAccountManager_GetNetworkMap(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	account, err := manager.AddAccount(expectedId, userId, "")
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

	_, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: PeerSystemMeta{},
		Name: "test-peer-2",
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
	_, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: PeerSystemMeta{},
		Name: "test-peer-2",
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	networkMap, err := manager.GetNetworkMap(peerKey1.PublicKey().String())
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

	expectedId := "test_account"
	userId := "account_creator"
	account, err := manager.AddAccount(expectedId, userId, "")
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

	_, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey1.PublicKey().String(),
		Meta: PeerSystemMeta{},
		Name: "test-peer-2",
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
	_, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey2.PublicKey().String(),
		Meta: PeerSystemMeta{},
		Name: "test-peer-2",
	})

	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	rules, err := manager.ListRules(account.Id)
	if err != nil {
		t.Errorf("expecting to get a list of rules, got failure %v", err)
		return
	}

	err = manager.DeleteRule(account.Id, rules[0].ID)
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
	group1.Peers = append(group1.Peers, peerKey1.PublicKey().String())
	group2.Peers = append(group2.Peers, peerKey2.PublicKey().String())

	err = manager.SaveGroup(account.Id, &group1)
	if err != nil {
		t.Errorf("expecting group1 to be added, got failure %v", err)
		return
	}
	err = manager.SaveGroup(account.Id, &group2)
	if err != nil {
		t.Errorf("expecting group2 to be added, got failure %v", err)
		return
	}

	rule.Name = "test"
	rule.Source = append(rule.Source, group1.ID)
	rule.Destination = append(rule.Destination, group2.ID)
	rule.Flow = TrafficFlowBidirect
	err = manager.SaveRule(account.Id, &rule)
	if err != nil {
		t.Errorf("expecting rule to be added, got failure %v", err)
		return
	}

	networkMap1, err := manager.GetNetworkMap(peerKey1.PublicKey().String())
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

	networkMap2, err := manager.GetNetworkMap(peerKey2.PublicKey().String())
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
	err = manager.SaveRule(account.Id, &rule)
	if err != nil {
		t.Errorf("expecting rule to be added, got failure %v", err)
		return
	}

	networkMap1, err = manager.GetNetworkMap(peerKey1.PublicKey().String())
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

	networkMap2, err = manager.GetNetworkMap(peerKey2.PublicKey().String())
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(networkMap2.Peers) != 0 {
		t.Errorf("expecting Account NetworkMap to have 0 peers, got %v", len(networkMap2.Peers))
	}
}
