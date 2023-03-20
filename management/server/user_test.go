package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUser_AddPATToUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId("account_id", "testuser", "")
	account.Peers["testpeer"] = &Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now()},
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:                   store,
		cacheMux:                sync.Mutex{},
		cacheLoading:            nil,
		peersUpdateManager:      nil,
		idpManager:              nil,
		cacheManager:            nil,
		ctx:                     nil,
		eventStore:              nil,
		singleAccountMode:       false,
		singleAccountModeDomain: "",
		dnsDomain:               "",
		peerLoginExpiry:         nil,
	}

	token := "someToken"
	pat := PersonalAccessToken{
		ID:             "tokenID",
		Description:    "some Description",
		HashedToken:    token,
		ExpirationDate: time.Time{},
		CreatedBy:      "testuser",
		CreatedAt:      time.Time{},
		LastUsed:       time.Time{},
	}

	err = am.AddPATToUser("account_id", "testuser", &pat)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	fileStore := am.Store.(*FileStore)
	tokenID := fileStore.HashedPAT2TokenID[token[:]]

	if tokenID == "" {
		t.Fatal("GetTokenIDByHashedToken failed after adding PAT")
	}

	assert.Equal(t, "tokenID", tokenID)

	userID := fileStore.TokenID2UserID[tokenID]
	if userID == "" {
		t.Fatal("GetUserByTokenId failed after adding PAT")
	}
	assert.Equal(t, "testuser", userID)
}

func TestUser_DeletePAT(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId("account_id", "testuser", "")
	account.Peers["testpeer"] = &Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now()},
	}
	account.Users["user1"] = &User{
		Id:         "user1",
		Role:       "admin",
		AutoGroups: nil,
		PATs: map[string]*PersonalAccessToken{
			"tokenID": {
				ID:             "tokenID",
				Description:    "some Description",
				HashedToken:    "SoMeHaShEdToKeN",
				ExpirationDate: time.Now().AddDate(0, 0, 7),
				CreatedBy:      "user1",
				CreatedAt:      time.Now(),
				LastUsed:       time.Now(),
			},
		},
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:                   store,
		cacheMux:                sync.Mutex{},
		cacheLoading:            nil,
		peersUpdateManager:      nil,
		idpManager:              nil,
		cacheManager:            nil,
		ctx:                     nil,
		eventStore:              nil,
		singleAccountMode:       false,
		singleAccountModeDomain: "",
		dnsDomain:               "",
		peerLoginExpiry:         nil,
	}

	err = am.DeletePAT("account_id", "user1", "tokenID")
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Nil(t, store.Accounts["account_id"].Users["user1"].PATs["tokenID"])
	assert.Empty(t, store.HashedPAT2TokenID["SoMeHaShEdToKeN"])
	assert.Empty(t, store.TokenID2UserID["tokenID"])
}
