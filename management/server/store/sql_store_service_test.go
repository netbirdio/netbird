package store

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
)

func TestSqlStore_GetAccount_PrivateServiceRoundtrip(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_private_svc", "testuser", "")
		require.NoError(t, store.SaveAccount(ctx, account))

		svc := &rpservice.Service{
			ID:           "svc-private",
			AccountID:    account.Id,
			Name:         "private-svc",
			Domain:       "private.example",
			ProxyCluster: "cluster.example",
			Enabled:      true,
			Mode:         rpservice.ModeHTTP,
			Private:      true,
			AccessGroups: []string{"grp-admins", "grp-ops"},
		}
		require.NoError(t, store.CreateService(ctx, svc))

		loaded, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Len(t, loaded.Services, 1)

		got := loaded.Services[0]
		assert.True(t, got.Private)
		assert.Equal(t, []string{"grp-admins", "grp-ops"}, got.AccessGroups)
	})
}

func TestSqlStore_GetAccount_ServiceRestrictionsRoundtrip(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_svc_restrictions", "testuser", "")
		require.NoError(t, store.SaveAccount(ctx, account))

		svc := &rpservice.Service{
			ID:        "svc-restrictions",
			AccountID: account.Id,
			Name:      "restricted-svc",
			Domain:    "restricted.example",
			Enabled:   true,
			Mode:      rpservice.ModeHTTP,
			Restrictions: rpservice.AccessRestrictions{
				AllowedCIDRs:     []string{"203.0.113.0/24"},
				AllowedCountries: []string{"US"},
				AllowMatch:       "any",
			},
		}
		require.NoError(t, store.CreateService(ctx, svc))

		loaded, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Len(t, loaded.Services, 1)

		// Restrictions are stored as a JSON blob; confirm the whole struct,
		// including allow_match, survives the read path (Postgres pgx path
		// included via runTestForAllEngines).
		got := loaded.Services[0].Restrictions
		assert.Equal(t, []string{"203.0.113.0/24"}, got.AllowedCIDRs)
		assert.Equal(t, []string{"US"}, got.AllowedCountries)
		assert.Equal(t, "any", got.AllowMatch)
	})
}
