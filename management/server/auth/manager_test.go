package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/auth"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestAuthManager_GetAccountInfoFromPAT(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	token := "nbp_9999EUDNdkeusjentDLSJEn1902u84390W6W"
	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := base64.StdEncoding.EncodeToString(hashedToken[:])
	account := &types.Account{
		Id: "account_id",
		Users: map[string]*types.User{"someUser": {
			Id: "someUser",
			PATs: map[string]*types.PersonalAccessToken{
				"tokenId": {
					ID:          "tokenId",
					UserID:      "someUser",
					HashedToken: encodedHashedToken,
				},
			},
		}},
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	manager := auth.NewManager(store, "", "", "", "", []string{}, false)

	user, pat, _, _, err := manager.GetPATInfo(context.Background(), token)
	if err != nil {
		t.Fatalf("Error when getting Account from PAT: %s", err)
	}

	assert.Equal(t, "account_id", user.AccountID)
	assert.Equal(t, "someUser", user.Id)
	assert.Equal(t, account.Users["someUser"].PATs["tokenId"].ID, pat.ID)
}

func TestAuthManager_MarkPATUsed(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	token := "nbp_9999EUDNdkeusjentDLSJEn1902u84390W6W"
	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := base64.StdEncoding.EncodeToString(hashedToken[:])
	account := &types.Account{
		Id: "account_id",
		Users: map[string]*types.User{"someUser": {
			Id: "someUser",
			PATs: map[string]*types.PersonalAccessToken{
				"tokenId": {
					ID:          "tokenId",
					HashedToken: encodedHashedToken,
				},
			},
		}},
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	manager := auth.NewManager(store, "", "", "", "", []string{}, false)

	err = manager.MarkPATUsed(context.Background(), "tokenId")
	if err != nil {
		t.Fatalf("Error when marking PAT used: %s", err)
	}

	account, err = store.GetAccount(context.Background(), "account_id")
	if err != nil {
		t.Fatalf("Error when getting account: %s", err)
	}
	assert.True(t, !account.Users["someUser"].PATs["tokenId"].GetLastUsed().IsZero())
}

func TestAuthManager_EnsureUserAccessByJWTGroups(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	userId := "user-id"
	domain := "test.domain"

	account := &types.Account{
		Id:     "account_id",
		Domain: domain,
		Users: map[string]*types.User{"someUser": {
			Id: "someUser",
		}},
		Settings: &types.Settings{},
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	// this has been validated and parsed by ValidateAndParseToken
	userAuth := nbcontext.UserAuth{
		AccountId:      account.Id,
		Domain:         domain,
		UserId:         userId,
		DomainCategory: "test-category",
		// Groups:         []string{"group1", "group2"},
	}

	// these tests only assert groups are parsed from token as per account settings
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"idp-groups": []interface{}{"group1", "group2"}})

	manager := auth.NewManager(store, "", "", "", "", []string{}, false)

	t.Run("JWT groups disabled", func(t *testing.T) {
		userAuth, err := manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.NoError(t, err, "ensure user access by JWT groups failed")
		require.Len(t, userAuth.Groups, 0, "account not enabled to ensure access by groups")
	})

	t.Run("User impersonated", func(t *testing.T) {
		userAuth, err := manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.NoError(t, err, "ensure user access by JWT groups failed")
		require.Len(t, userAuth.Groups, 0, "account not enabled to ensure access by groups")
	})

	t.Run("User PAT", func(t *testing.T) {
		userAuth, err := manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.NoError(t, err, "ensure user access by JWT groups failed")
		require.Len(t, userAuth.Groups, 0, "account not enabled to ensure access by groups")
	})

	t.Run("JWT groups enabled without claim name", func(t *testing.T) {
		account.Settings.JWTGroupsEnabled = true
		err := store.SaveAccount(context.Background(), account)
		require.NoError(t, err, "save account failed")

		userAuth, err := manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.NoError(t, err, "ensure user access by JWT groups failed")
		require.Len(t, userAuth.Groups, 0, "account missing groups claim name")
	})

	t.Run("JWT groups enabled without allowed groups", func(t *testing.T) {
		account.Settings.JWTGroupsEnabled = true
		account.Settings.JWTGroupsClaimName = "idp-groups"
		err := store.SaveAccount(context.Background(), account)
		require.NoError(t, err, "save account failed")

		userAuth, err := manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.NoError(t, err, "ensure user access by JWT groups failed")
		require.Len(t, userAuth.Groups, 0, "account missing allowed groups")
	})

	t.Run("User in allowed JWT groups", func(t *testing.T) {
		account.Settings.JWTGroupsEnabled = true
		account.Settings.JWTGroupsClaimName = "idp-groups"
		account.Settings.JWTAllowGroups = []string{"group1"}
		err := store.SaveAccount(context.Background(), account)
		require.NoError(t, err, "save account failed")

		userAuth, err := manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.NoError(t, err, "ensure user access by JWT groups failed")

		require.Equal(t, []string{"group1", "group2"}, userAuth.Groups, "group parsed do not match")
	})

	t.Run("User not in allowed JWT groups", func(t *testing.T) {
		account.Settings.JWTGroupsEnabled = true
		account.Settings.JWTGroupsClaimName = "idp-groups"
		account.Settings.JWTAllowGroups = []string{"not-a-group"}
		err := store.SaveAccount(context.Background(), account)
		require.NoError(t, err, "save account failed")

		_, err = manager.EnsureUserAccessByJWTGroups(context.Background(), userAuth, token)
		require.Error(t, err, "ensure user access is not in allowed groups")
	})
}

func TestAuthManager_ValidateAndParseToken(t *testing.T) {
	// @todo should be an integration test that covers the validator and extractor with valid JWT
}
