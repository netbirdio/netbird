package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestGetUsersFromAccount_MissingIDPUserDoesNotReloadWarmCache(t *testing.T) {
	for _, tc := range []struct {
		name            string
		presentInIDP    bool
		serviceUser     bool
		integrationUser bool
		pendingApproval bool
	}{
		{name: "present regular user", presentInIDP: true},
		{name: "missing regular user"},
		{name: "missing pending user", pendingApproval: true},
		{name: "missing service user", serviceUser: true},
		{name: "missing integration user", integrationUser: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
			t.Setenv(cache.RedisStoreEnvVar, "")
			t.Setenv("NB_IDP_CACHE_REDIS_ADDRESS", "")

			testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
			require.NoError(t, err)
			t.Cleanup(cleanup)

			account := newAccountWithId(ctx, "cache-account", "owner", "", "owner@example.com", "Owner", false)
			other := types.NewRegularUser("other", "other@example.com", "Other")
			other.AccountID = account.Id
			other.IsServiceUser = tc.serviceUser
			other.Blocked = tc.pendingApproval
			other.PendingApproval = tc.pendingApproval
			if tc.integrationUser {
				other.Issued = types.UserIssuedIntegration
			}
			account.Users[other.Id] = other
			require.NoError(t, testStore.SaveAccount(ctx, account))
			storedBefore, err := testStore.GetUserByUserID(ctx, store.LockingStrengthNone, other.Id)
			require.NoError(t, err)

			profiles := []*idp.UserData{{ID: account.CreatedBy, Name: "Owner", Email: "owner@example.com"}}
			if tc.presentInIDP {
				profiles = append(profiles, &idp.UserData{ID: other.Id, Name: other.Name, Email: other.Email})
			}
			keycloak, fetches := newCacheTestKeycloakManager(t, profiles)
			cacheStore, err := cache.NewStore(ctx, time.Hour, 0, cache.DefaultIDPCacheOpenConn)
			require.NoError(t, err)
			am := &DefaultAccountManager{
				Store:                testStore,
				ctx:                  ctx,
				idpManager:           keycloak,
				cacheLoading:         make(map[string]chan struct{}),
				permissionsManager:   permissions.NewManager(testStore),
				externalCacheManager: cache.NewUserDataCache(cacheStore),
			}
			am.cacheManager = cache.NewAccountUserDataCache(am.loadAccount, cacheStore)
			t.Cleanup(func() { assert.NoError(t, am.cacheManager.Close()) })

			users, err := am.GetUsersFromAccount(ctx, account.Id, account.CreatedBy)
			require.NoError(t, err)
			require.Contains(t, users, account.CreatedBy, "the owner must remain visible")
			// The loadable cache stores fetched results asynchronously.
			require.Eventually(t, func() bool {
				_, err := cacheStore.Get(ctx, account.Id)
				return err == nil
			}, time.Second, time.Millisecond, "the initial IdP result must be cached")
			warmFetches := fetches.Load()
			require.Positive(t, warmFetches, "warming the cache must exercise the real IdP client")

			for range 3 {
				users, err = am.GetUsersFromAccount(ctx, account.Id, account.CreatedBy)
				require.NoError(t, err)
				require.Contains(t, users, account.CreatedBy, "owner requests must still succeed")
				assert.Equal(t, "owner@example.com", users[account.CreatedBy].Email, "owner data must be preserved")
			}
			t.Logf("IdP user-list fetches: warm=%d, after three owner requests=%d", warmFetches, fetches.Load())
			assert.Equal(t, warmFetches, fetches.Load(), "a confirmed missing user must not reload the warm cache on every owner request")

			if !tc.presentInIDP && !tc.serviceUser && !tc.integrationUser {
				userData, err := am.lookupUserInCache(ctx, other.Id, account.Id)
				require.NoError(t, err)
				assert.Nil(t, userData, "a cache optimization must not fabricate an IdP identity")
			}
			if tc.pendingApproval {
				_, err := am.GetUsersFromAccount(ctx, account.Id, other.Id)
				require.Error(t, err)
				statusErr, ok := status.FromError(err)
				require.True(t, ok, "a pending user must receive a typed permission error")
				assert.Equal(t, status.PermissionDenied, statusErr.Type(), "pending users must remain denied")
			}

			storedAfter, err := testStore.GetUserByUserID(ctx, store.LockingStrengthNone, other.Id)
			require.NoError(t, err)
			assert.Equal(t, storedBefore, storedAfter, "cache lookups must not change the stored user")
		})
	}
}

func newCacheTestKeycloakManager(t *testing.T, users []*idp.UserData) (*idp.KeycloakManager, *atomic.Int64) {
	t.Helper()

	profiles := make([]map[string]string, 0, len(users))
	for _, user := range users {
		profiles = append(profiles, map[string]string{"id": user.ID, "username": user.Name, "email": user.Email})
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-keycloak-secret"))
	require.NoError(t, err)

	var fetches atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"expires_in":   3600,
			"token_type":   "Bearer",
		}))
	})
	mux.HandleFunc("GET /admin/users/count", func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprint(w, len(profiles))
		assert.NoError(t, err)
	})
	mux.HandleFunc("GET /admin/users", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		assert.NoError(t, json.NewEncoder(w).Encode(profiles))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	manager, err := idp.NewKeycloakManager(idp.KeycloakClientConfig{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		AdminEndpoint: server.URL + "/admin",
		TokenEndpoint: server.URL + "/token",
		GrantType:     "client_credentials",
	}, nil)
	require.NoError(t, err)
	return manager, &fetches
}
