package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// decodeServiceRouterConfig finds the llm_router middleware on the synthesised
// service's single target and decodes its config — the model→provider routing
// table the proxy authorises against.
func decodeServiceRouterConfig(t *testing.T, svc *rpservice.Service) routerConfig {
	t.Helper()
	require.NotEmpty(t, svc.Targets, "synth service must carry a target")
	for _, mw := range svc.Targets[0].Options.Middlewares {
		if mw.ID == middlewareIDLLMRouter {
			var cfg routerConfig
			require.NoError(t, json.Unmarshal(mw.ConfigJSON, &cfg), "router config must decode")
			return cfg
		}
	}
	t.Fatal("llm_router middleware not present on synthesised service")
	return routerConfig{}
}

// decodeMappingRouterConfig is the proto-wire equivalent: it pulls the
// llm_router config off the ProxyMapping the proxy actually receives.
func decodeMappingRouterConfig(t *testing.T, m *proto.ProxyMapping) routerConfig {
	t.Helper()
	require.NotEmpty(t, m.GetPath(), "mapping must carry a path")
	for _, mw := range m.GetPath()[0].GetOptions().GetMiddlewares() {
		if mw.GetId() == middlewareIDLLMRouter {
			var cfg routerConfig
			require.NoError(t, json.Unmarshal(mw.GetConfigJson(), &cfg), "wire router config must decode")
			return cfg
		}
	}
	t.Fatal("llm_router middleware not present on proxy mapping")
	return routerConfig{}
}

// TestSynthesizeServices_RealStore_SurvivesStatusToggle drives synthesis through
// a REAL sqlite store (Save → gorm/JSON serialize → reload → decrypt) instead of
// a MockStore, so it exercises the field round-trip that a provider/policy edit
// actually hits. Mock-based tests can't catch a field that dies in persistence;
// this one can. It then performs the exact operation that reproduced the live
// 403 — disable then re-enable the provider — and asserts the re-enabled state
// is fully routable again.
func TestSynthesizeServices_RealStore_SurvivesStatusToggle(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	assertRoutable := func(t *testing.T, stage string) {
		services, err := SynthesizeServices(ctx, s, testAccountID)
		require.NoError(t, err, stage)
		require.Len(t, services, 1, "%s: exactly one synth service expected", stage)
		svc := services[0]

		assert.True(t, svc.Private, "%s: synth service must be Private after store round-trip", stage)
		assert.Equal(t, []string{"grp-eng"}, svc.AccessGroups, "%s: AccessGroups must survive the round-trip", stage)

		m := svc.ToProtoMapping(rpservice.Update, "", rpproxy.OIDCValidationConfig{})
		assert.True(t, m.GetPrivate(), "%s: proto mapping Private must be true (proxy gates tunnel-peer auth on it)", stage)

		cfg := decodeServiceRouterConfig(t, svc)
		require.Len(t, cfg.Providers, 1, "%s: the enabled+linked provider must appear in the router config", stage)
		assert.Equal(t, []string{"gpt-5.4"}, cfg.Providers[0].Models, "%s: provider models must reach the route", stage)
		assert.Equal(t, []string{"grp-eng"}, cfg.Providers[0].AllowedGroupIDs, "%s: policy source groups must reach the route", stage)
	}

	assertRoutable(t, "initial")

	provider.Enabled = false
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	disabled, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err, "synthesis must not error with a disabled provider")
	for _, svc := range disabled {
		assert.Empty(t, decodeServiceRouterConfig(t, svc).Providers,
			"a disabled provider must not appear in the router config (otherwise it would route while off)")
	}

	provider.Enabled = true
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	assertRoutable(t, "after disable->enable")
}

// captureController is a proxy.Controller that records the mappings reconcile
// pushes, so the test can inspect the exact wire payload — Private flag and
// router config included.
type captureController struct {
	rpproxy.Controller
	pushed []*proto.ProxyMapping
}

func (c *captureController) GetOIDCValidationConfig() rpproxy.OIDCValidationConfig {
	return rpproxy.OIDCValidationConfig{}
}

func (c *captureController) SendServiceUpdateToCluster(_ context.Context, _ string, update *proto.ProxyMapping, _ string) {
	c.pushed = append(c.pushed, update)
}

// noopAccountManager satisfies the reconcile path's accountManager dependency.
type noopAccountManager struct {
	account.Manager
}

func (noopAccountManager) UpdateAccountPeers(context.Context, string, nbtypes.UpdateReason) {}

// TestReconcile_RealStore_PushesPrivateAfterStatusToggle reproduces the live
// path end-to-end below the gRPC boundary: a real store + the real
// managerImpl.reconcile + a capturing proxy controller. It runs the operation
// that broke in production — provider disable then re-enable — and asserts the
// mapping reconcile pushes to the cluster after re-enable is Private=true and
// carries the routable provider. If reconcile ever pushes private=false (the
// symptom that left UserGroups empty → no_authorised_provider), this fails.
func TestReconcile_RealStore_PushesPrivateAfterStatusToggle(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	ctrl := &captureController{}
	m := &managerImpl{
		store:           s,
		accountManager:  noopAccountManager{},
		proxyController: ctrl,
		reconcileCache:  make(map[string]map[string]*proto.ProxyMapping),
	}

	m.reconcile(ctx, testAccountID) // initial, provider enabled

	provider.Enabled = false
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	m.reconcile(ctx, testAccountID) // disabled

	provider.Enabled = true
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	m.reconcile(ctx, testAccountID) // re-enabled — the reproduction step

	require.NotEmpty(t, ctrl.pushed, "reconcile must push at least one mapping")
	last := ctrl.pushed[len(ctrl.pushed)-1]

	assert.Equal(t, newSynthTestSettings().Endpoint(), last.GetDomain(), "synth domain on the wire")
	assert.True(t, last.GetPrivate(),
		"reconcile-pushed mapping after re-enable MUST be Private=true; a false here is the exact bug — the proxy skips ValidateTunnelPeer, UserGroups stays empty, and llm_router denies no_authorised_provider")

	cfg := decodeMappingRouterConfig(t, last)
	require.Len(t, cfg.Providers, 1, "re-enabled provider must be back in the pushed router config")
	assert.Equal(t, []string{"gpt-5.4"}, cfg.Providers[0].Models, "model must be routable again after re-enable")
	assert.Equal(t, []string{"grp-eng"}, cfg.Providers[0].AllowedGroupIDs, "authorised groups must be present after re-enable")
}
