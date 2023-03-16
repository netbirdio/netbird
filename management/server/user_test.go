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
	store.SaveAccount(account)

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
		ID:             "tokenId",
		Description:    "some Description",
		HashedToken:    token,
		ExpirationDate: time.Time{},
		CreatedBy:      "testuser",
		CreatedAt:      time.Time{},
		LastUsed:       time.Time{},
	}

	am.AddPATToUser("account_id", "testuser", pat)

	fileStore := am.Store.(*FileStore)
	tokenId := fileStore.HashedPAT2TokenID[string(token[:])]

	if tokenId == "" {
		t.Fatal("GetTokenIDByHashedToken failed after adding PAT")
	}

	assert.Equal(t, "tokenId", tokenId)

	userId := fileStore.TokenID2UserID[tokenId]
	if userId == "" {
		t.Fatal("GetUserByTokenId failed after adding PAT")
	}
	assert.Equal(t, "testuser", userId)
}
