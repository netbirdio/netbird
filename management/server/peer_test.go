package server

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"testing"
)

func TestAccountManager_GetNetworkMap(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	account, err := manager.AddAccount(expectedId, userId)
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

	_, err = manager.AddPeer(setupKey.Key, &Peer{
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
	_, err = manager.AddPeer(setupKey.Key, &Peer{
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
		t.Errorf("expecting Account NetworkMap to have peer with a key %s, got %s", peerKey2.PublicKey().String(), networkMap.Peers[0].Key)
	}

}
