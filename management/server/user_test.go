package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	mockAccountID = "accountID"
	mockUserID    = "userID"
	mockTokenID   = "tokenID"
	mockToken     = "SoMeHaShEdToKeN"
)

func TestUser_AddPATToUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store: store,
	}

	pat := PersonalAccessToken{
		ID:          mockTokenID,
		HashedToken: mockToken,
	}

	err = am.AddPATToUser(mockAccountID, mockUserID, &pat)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	fileStore := am.Store.(*FileStore)
	tokenID := fileStore.HashedPAT2TokenID[mockToken[:]]

	if tokenID == "" {
		t.Fatal("GetTokenIDByHashedToken failed after adding PAT")
	}

	assert.Equal(t, mockTokenID, tokenID)

	userID := fileStore.TokenID2UserID[tokenID]
	if userID == "" {
		t.Fatal("GetUserByTokenId failed after adding PAT")
	}
	assert.Equal(t, mockUserID, userID)
}

func TestUser_DeletePAT(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockUserID] = &User{
		Id: mockUserID,
		PATs: map[string]*PersonalAccessToken{
			mockTokenID: {
				ID:          mockTokenID,
				HashedToken: mockToken,
			},
		},
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store: store,
	}

	err = am.DeletePAT(mockAccountID, mockUserID, mockTokenID)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Nil(t, store.Accounts[mockAccountID].Users[mockUserID].PATs[mockTokenID])
	assert.Empty(t, store.HashedPAT2TokenID[mockToken])
	assert.Empty(t, store.TokenID2UserID[mockTokenID])
}
