package server

import (
	"testing"
)

func TestNewStore(t *testing.T) {
	storeFile := t.TempDir() + "/store.json"
	store, err := NewStore(storeFile)
	if err != nil {
		return
	}

	if store.Accounts == nil || len(store.Accounts) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}

	if store.SetupKeyId2AccountId == nil || len(store.SetupKeyId2AccountId) != 0 {
		t.Errorf("expected to create a new empty SetupKeyId2AccountId map when creating a new FileStore")
	}

	if store.PeerKeyId2AccountId == nil || len(store.PeerKeyId2AccountId) != 0 {
		t.Errorf("expected to create a new empty PeerKeyId2AccountId map when creating a new FileStore")
	}

	if store.UserId2AccountId == nil || len(store.UserId2AccountId) != 0 {
		t.Errorf("expected to create a new empty UserId2AccountId map when creating a new FileStore")
	}

}
