package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestNewStore(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())

	if store.Accounts == nil || len(store.Accounts) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}

	if store.SetupKeyID2AccountID == nil || len(store.SetupKeyID2AccountID) != 0 {
		t.Errorf("expected to create a new empty SetupKeyID2AccountID map when creating a new FileStore")
	}

	if store.PeerKeyID2AccountID == nil || len(store.PeerKeyID2AccountID) != 0 {
		t.Errorf("expected to create a new empty PeerKeyID2AccountID map when creating a new FileStore")
	}

	if store.UserID2AccountID == nil || len(store.UserID2AccountID) != 0 {
		t.Errorf("expected to create a new empty UserID2AccountID map when creating a new FileStore")
	}

	if store.HashedPAT2TokenID == nil || len(store.HashedPAT2TokenID) != 0 {
		t.Errorf("expected to create a new empty HashedPAT2TokenID map when creating a new FileStore")
	}

	if store.TokenID2UserID == nil || len(store.TokenID2UserID) != 0 {
		t.Errorf("expected to create a new empty TokenID2UserID map when creating a new FileStore")
	}
}

func TestStore(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())

	account := newAccountWithId(context.Background(), "account_id", "testuser", "")
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}
	account.Groups["all"] = &group.Group{
		ID:    "all",
		Name:  "all",
		Peers: []string{"testpeer"},
	}
	account.Policies = append(account.Policies, &Policy{
		ID:      "all",
		Name:    "all",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:           "all",
				Name:         "all",
				Sources:      []string{"all"},
				Destinations: []string{"all"},
			},
		},
	})
	account.Policies = append(account.Policies, &Policy{
		ID:      "dmz",
		Name:    "dmz",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:           "dmz",
				Name:         "dmz",
				Enabled:      true,
				Sources:      []string{"all"},
				Destinations: []string{"all"},
			},
		},
	})

	// SaveAccount should trigger persist
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		return
	}

	restored, err := NewFileStore(context.Background(), store.storeFile, nil)
	if err != nil {
		return
	}

	restoredAccount := restored.Accounts[account.Id]
	if restoredAccount == nil {
		t.Errorf("failed to restore a FileStore file - missing Account %s", account.Id)
		return
	}

	if restoredAccount.Peers["testpeer"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Peer testpeer")
	}

	if restoredAccount.CreatedBy != "testuser" {
		t.Errorf("failed to restore a FileStore file - missing Account CreatedBy")
	}

	if restoredAccount.Users["testuser"] == nil {
		t.Errorf("failed to restore a FileStore file - missing User testuser")
	}

	if restoredAccount.Network == nil {
		t.Errorf("failed to restore a FileStore file - missing Network")
	}

	if restoredAccount.Groups["all"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Group all")
	}

	if len(restoredAccount.Policies) != 2 {
		t.Errorf("failed to restore a FileStore file - missing Policies")
		return
	}

	assert.Equal(t, account.Policies[0], restoredAccount.Policies[0], "failed to restore a FileStore file - missing Policy all")
	assert.Equal(t, account.Policies[1], restoredAccount.Policies[1], "failed to restore a FileStore file - missing Policy dmz")
}

func newStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Errorf("failed creating a new store")
	}

	return store
}
