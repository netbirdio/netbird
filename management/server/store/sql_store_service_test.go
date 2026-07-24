package store

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

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

// TestSqlStore_GetAccount_ServiceTargetOptionsRoundtrip guards the Postgres pgx
// read path (getServices) against silently dropping columns present on the gorm
// model. Before the fix these fields loaded correctly on SQLite but came back
// zero-valued on Postgres because the hand-written SELECT and scan omitted them.
func TestSqlStore_GetAccount_ServiceTargetOptionsRoundtrip(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_svc_opts", "testuser", "")
		require.NoError(t, store.SaveAccount(ctx, account))

		renewedAt := time.Now().UTC().Truncate(time.Second)
		targetPath := "/api"
		svc := &rpservice.Service{
			ID:        "svc-opts",
			AccountID: account.Id,
			Name:      "opts-svc",
			Domain:    "opts.example",
			Enabled:   true,
			Mode:      rpservice.ModeHTTP,
			Restrictions: rpservice.AccessRestrictions{
				AllowedCIDRs:     []string{"10.0.0.0/8"},
				BlockedCountries: []string{"XX"},
				CrowdSecMode:     "block",
			},
			Meta: rpservice.Meta{
				LastRenewedAt: &renewedAt,
			},
			Targets: []*rpservice.Target{
				{
					AccountID:     account.Id,
					ServiceID:     "svc-opts",
					Path:          &targetPath,
					Host:          "backend.internal",
					Port:          8080,
					Protocol:      "http",
					TargetId:      "tgt-1",
					Enabled:       true,
					ProxyProtocol: true,
					Options: rpservice.TargetOptions{
						SkipTLSVerify:           true,
						RequestTimeout:          30 * time.Second,
						SessionIdleTimeout:      5 * time.Minute,
						PathRewrite:             rpservice.PathRewritePreserve,
						CustomHeaders:           map[string]string{"X-Foo": "bar"},
						DirectUpstream:          true,
						CaptureMaxRequestBytes:  1024,
						CaptureMaxResponseBytes: 2048,
						CaptureContentTypes:     []string{"application/json"},
						AgentNetwork:            true,
						DisableAccessLog:        true,
					},
				},
			},
		}
		require.NoError(t, store.CreateService(ctx, svc))

		loaded, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Len(t, loaded.Services, 1)

		got := loaded.Services[0]
		assert.Equal(t, []string{"10.0.0.0/8"}, got.Restrictions.AllowedCIDRs, "restrictions allowed CIDRs")
		assert.Equal(t, []string{"XX"}, got.Restrictions.BlockedCountries, "restrictions blocked countries")
		assert.Equal(t, "block", got.Restrictions.CrowdSecMode, "restrictions crowdsec mode")
		require.NotNil(t, got.Meta.LastRenewedAt, "meta last renewed at")
		assert.WithinDuration(t, renewedAt, *got.Meta.LastRenewedAt, time.Second, "meta last renewed at")

		require.Len(t, got.Targets, 1)
		tg := got.Targets[0]
		assert.True(t, tg.ProxyProtocol, "target proxy protocol")
		assert.True(t, tg.Options.SkipTLSVerify, "options skip TLS verify")
		assert.Equal(t, 30*time.Second, tg.Options.RequestTimeout, "options request timeout")
		assert.Equal(t, 5*time.Minute, tg.Options.SessionIdleTimeout, "options session idle timeout")
		assert.Equal(t, rpservice.PathRewritePreserve, tg.Options.PathRewrite, "options path rewrite")
		assert.Equal(t, map[string]string{"X-Foo": "bar"}, tg.Options.CustomHeaders, "options custom headers")
		assert.True(t, tg.Options.DirectUpstream, "options direct upstream")
		assert.Equal(t, int64(1024), tg.Options.CaptureMaxRequestBytes, "options capture max request bytes")
		assert.Equal(t, int64(2048), tg.Options.CaptureMaxResponseBytes, "options capture max response bytes")
		assert.Equal(t, []string{"application/json"}, tg.Options.CaptureContentTypes, "options capture content types")
		assert.True(t, tg.Options.AgentNetwork, "options agent network")
		assert.True(t, tg.Options.DisableAccessLog, "options disable access log")
	})
}
