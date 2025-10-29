package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nbauth "github.com/netbirdio/netbird/shared/auth"
	nbjwt "github.com/netbirdio/netbird/shared/auth/jwt"
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
	userAuth := nbauth.UserAuth{
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
		require.Equal(t, []string{"group1", "group2"}, userAuth.Groups, "group parsed do not match")
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "max-age=30") // set a 30s expiry to these keys
		http.ServeFile(w, r, "test_data/jwks.json")
	}))
	defer server.Close()

	issuer := "http://issuer.local"
	audience := "http://audience.local"
	userIdClaim := "" // defaults to "sub"

	// we're only testing with RSA256
	keyData, _ := os.ReadFile("test_data/sample_key")
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	keyId := "test-key"

	// note, we can use a nil store because ValidateAndParseToken does not use it in it's flow
	manager := auth.NewManager(nil, issuer, audience, server.URL, userIdClaim, []string{audience}, false)

	customClaim := func(name string) string {
		return fmt.Sprintf("%s/%s", audience, name)
	}

	lastLogin := time.Date(2025, 2, 12, 14, 25, 26, 0, time.UTC) //"2025-02-12T14:25:26.186Z"

	tests := []struct {
		name      string
		tokenFunc func() string
		expected  *nbauth.UserAuth // nil indicates expected error
	}{
		{
			name: "Valid with custom claims",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss":                                   issuer,
					"aud":                                   []string{audience},
					"iat":                                   time.Now().Unix(),
					"exp":                                   time.Now().Add(time.Hour * 1).Unix(),
					"sub":                                   "user-id|123",
					customClaim(nbjwt.AccountIDSuffix):      "account-id|567",
					customClaim(nbjwt.DomainIDSuffix):       "http://localhost",
					customClaim(nbjwt.DomainCategorySuffix): "private",
					customClaim(nbjwt.LastLoginSuffix):      lastLogin.Format(time.RFC3339),
					customClaim(nbjwt.Invited):              false,
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
			expected: &nbauth.UserAuth{
				UserId:         "user-id|123",
				AccountId:      "account-id|567",
				Domain:         "http://localhost",
				DomainCategory: "private",
				LastLogin:      lastLogin,
				Invited:        false,
			},
		},
		{
			name: "Valid without custom claims",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss": issuer,
					"aud": []string{audience},
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
					"sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
			expected: &nbauth.UserAuth{
				UserId: "user-id|123",
			},
		},
		{
			name: "Expired token",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss": issuer,
					"aud": []string{audience},
					"iat": time.Now().Add(time.Hour * -2).Unix(),
					"exp": time.Now().Add(time.Hour * -1).Unix(),
					"sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
		},
		{
			name: "Not yet valid",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss": issuer,
					"aud": []string{audience},
					"iat": time.Now().Add(time.Hour).Unix(),
					"exp": time.Now().Add(time.Hour * 2).Unix(),
					"sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
		},
		{
			name: "Invalid signature",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss": issuer,
					"aud": []string{audience},
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
					"sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				parts := strings.Split(tokenString, ".")
				parts[2] = "invalid-signature"
				return strings.Join(parts, ".")
			},
		},
		{
			name: "Invalid issuer",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss": "not-the-issuer",
					"aud": []string{audience},
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
					"sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
		},
		{
			name: "Invalid audience",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss": issuer,
					"aud": []string{"not-the-audience"},
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
					"sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
		},
		{
			name: "Invalid user claim",
			tokenFunc: func() string {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = keyId
				token.Claims = jwt.MapClaims{
					"iss":     issuer,
					"aud":     []string{audience},
					"iat":     time.Now().Unix(),
					"exp":     time.Now().Add(time.Hour).Unix(),
					"not-sub": "user-id|123",
				}
				tokenString, _ := token.SignedString(key)
				return tokenString
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := tt.tokenFunc()

			userAuth, token, err := manager.ValidateAndParseToken(context.Background(), tokenString)

			if tt.expected != nil {
				assert.NoError(t, err)
				assert.True(t, token.Valid)
				assert.Equal(t, *tt.expected, userAuth)
			} else {
				assert.Error(t, err)
				assert.Nil(t, token)
				assert.Empty(t, userAuth)
			}
		})
	}

}
