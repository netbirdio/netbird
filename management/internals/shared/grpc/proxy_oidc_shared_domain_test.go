package grpc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	servicemanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestGetOIDCURLSharedDomainSessionCode(t *testing.T) {
	ctx := context.Background()
	s, err := store.NewStore(ctx, types.SqliteStoreEngine, t.TempDir(), nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close(ctx)) })
	require.NoError(t, s.SaveAccount(ctx, &types.Account{Id: "account"}))
	for _, svc := range []*service.Service{
		{ID: "l4", AccountID: "account", Domain: "SHARED.EXAMPLE.COM.", Mode: service.ModeTCP, ProxyCluster: "l4-cluster"},
		{ID: "http", AccountID: "account", Domain: "shared.example.com", Mode: service.ModeHTTP, ProxyCluster: "http-cluster"},
	} {
		require.NoError(t, s.CreateService(ctx, svc))
	}
	pm, err := proxymanager.NewManager(s, noop.NewMeterProvider().Meter("test"))
	require.NoError(t, err)
	_, err = pm.Connect(ctx, "l4-proxy", "l4-session", "l4-cluster", "127.0.0.1", "0.80.0", nil, nil)
	require.NoError(t, err)

	var issuer string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}))
	}))
	t.Cleanup(idp.Close)
	issuer = idp.URL
	c, err := cache.NewStore(ctx, time.Minute, time.Minute, 100)
	require.NoError(t, err)
	srv := nbgrpc.NewProxyServiceServer(nil, nil, nbgrpc.NewSingleUseStore(ctx, c), nbgrpc.ProxyOIDCConfig{
		Issuer: issuer, ClientID: "test", CallbackURL: "https://management.example.com/callback",
	}, nil, nil, nil, pm, nil)
	t.Cleanup(srv.Close)
	srv.SetServiceManager(servicemanager.NewManager(s, nil, nil, nil, nil, nil))

	for _, tc := range []struct {
		name, version string
		wantCode      bool
	}{
		{name: "capable HTTP cluster", version: "0.81.0", wantCode: true},
		{name: "legacy HTTP cluster", version: "0.80.0", wantCode: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pm.Connect(ctx, "http-proxy", "http-session", "http-cluster", "127.0.0.1", tc.version, nil, nil)
			require.NoError(t, err)
			redirect := "https://SHARED.EXAMPLE.COM./callback"
			resp, err := srv.GetOIDCURL(ctx, &proto.GetOIDCURLRequest{AccountId: "account", Id: "http", RedirectUrl: redirect})
			require.NoError(t, err)
			authURL, err := url.Parse(resp.GetUrl())
			require.NoError(t, err)
			state := authURL.Query().Get("state")
			verifier, gotRedirect, useCode, err := srv.ValidateState(state)
			require.NoError(t, err)
			assert.NotEmpty(t, verifier, "the HTTP owner's login must retain its PKCE verifier")
			assert.Equal(t, redirect, gotRedirect, "the signed state must retain the requested redirect")
			assert.Equal(t, tc.wantCode, useCode, "session handoff must use the HTTP cluster's capability")
			_, _, _, err = srv.ValidateState(state)
			assert.Error(t, err, "OIDC state must only be consumed once")
		})
	}
	for _, tc := range []struct{ account, id string }{
		{account: "account", id: "l4"},
		{account: "another-account", id: "http"},
		{account: "account", id: ""},
	} {
		resp, err := srv.GetOIDCURL(ctx, &proto.GetOIDCURLRequest{
			AccountId: tc.account, Id: tc.id, RedirectUrl: "https://shared.example.com/callback",
		})
		assert.Nil(t, resp, "a request that does not identify the HTTP owner must not start login")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), "only the HTTP owner may authorize this redirect")
	}
}
