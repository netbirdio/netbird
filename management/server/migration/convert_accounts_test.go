package main

import (
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/util"
	"path/filepath"
	"testing"
)

func TestConvertAccounts(t *testing.T) {

	storeDir := t.TempDir()

	err := util.CopyFileContents("../testdata/storev1.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := server.NewStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}

	convertedStore, err := server.NewStore(filepath.Join(storeDir, "converted"))
	if err != nil {
		t.Fatal(err)
	}

	err = Convert(store, convertedStore)
	if err != nil {
		t.Fatal(err)
	}

	if len(store.Accounts) != len(convertedStore.Accounts) {
		t.Errorf("expecting the same number of accounts after conversion")
	}

	for _, account := range store.Accounts {
		convertedAccount, err := convertedStore.GetUserAccount(account.Id)
		if err != nil || convertedAccount == nil {
			t.Errorf("expecting Account %s to be converted", account.Id)
			return
		}
		if convertedAccount.CreatedBy != account.Id {
			t.Errorf("expecting converted Account.CreatedBy field to be equal to the old Account.Id")
			return
		}
		if convertedAccount.Id == account.Id {
			t.Errorf("expecting converted Account.Id to be different from Account.Id")
			return
		}
		if len(convertedAccount.Users) != 1 {
			t.Errorf("expecting converted Account.Users to be of size 1")
			return
		}
		user := convertedAccount.Users[account.Id]
		if user == nil {
			t.Errorf("expecting to find a user in converted Account.Users")
			return
		}
		if user.Role != server.UserRoleAdmin {
			t.Errorf("expecting to find a user in converted Account.Users with a role Admin")
			return
		}

		for peerId := range account.Peers {
			convertedPeer := convertedAccount.Peers[peerId]
			if convertedPeer == nil {
				t.Errorf("expecting Account Peer of StoreV1 to be found in StoreV2")
				return
			}
		}

	}

}
