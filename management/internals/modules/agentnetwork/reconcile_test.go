package agentnetwork

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func newReconcileMgr(t *testing.T, ctrl *gomock.Controller) (*managerImpl, *store.MockStore, *proxy.MockController) {
	t.Helper()
	mockStore := store.NewMockStore(ctrl)
	mockProxy := proxy.NewMockController(ctrl)
	return &managerImpl{
		store:           mockStore,
		proxyController: mockProxy,
		reconcileCache:  make(map[string]map[string]*proto.ProxyMapping),
	}, mockStore, mockProxy
}

func newReconcileTestProvider() *types.Provider {
	return &types.Provider{
		ID:                "prov-1",
		AccountID:         "acct-1",
		ProviderID:        "openai_api",
		Name:              "OpenAI",
		UpstreamURL:       "https://api.openai.com",
		APIKey:            "sk-test-key",
		Enabled:           true,
		SessionPrivateKey: "test-priv-key",
		SessionPublicKey:  "test-pub-key",
	}
}

func newReconcileTestPolicy(providerID, sourceGroupID string) *types.Policy {
	return &types.Policy{
		ID:                     "pol-1",
		AccountID:              "acct-1",
		Name:                   "engineers",
		Enabled:                true,
		SourceGroups:           []string{sourceGroupID},
		DestinationProviderIDs: []string{providerID},
	}
}

func newReconcileTestSettings() *types.Settings {
	return &types.Settings{
		AccountID: "acct-1",
		Cluster:   "eu.proxy.netbird.io",
		Subdomain: "violet",
	}
}

func expectReconcileSynthInputs(mockStore *store.MockStore, ctx context.Context, providers []*types.Provider, policies []*types.Policy, guardrails []*types.Guardrail) {
	mockStore.EXPECT().
		GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").
		Return(newReconcileTestSettings(), nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "acct-1").
		Return(providers, nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, "acct-1").
		Return(policies, nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, "acct-1").
		Return(guardrails, nil)
}

func TestReconcile_FirstSynth_EmitsCreate(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, mockProxy := newReconcileMgr(t, ctrl)
	provider := newReconcileTestProvider()
	policy := newReconcileTestPolicy(provider.ID, "grp-eng")

	expectReconcileSynthInputs(mockStore, ctx, []*types.Provider{provider}, []*types.Policy{policy}, []*types.Guardrail{})
	mockProxy.EXPECT().GetOIDCValidationConfig().Return(proxy.OIDCValidationConfig{})

	var sentMappings []*proto.ProxyMapping
	mockProxy.EXPECT().
		SendServiceUpdateToCluster(ctx, "acct-1", gomock.Any(), "eu.proxy.netbird.io").
		Do(func(_ context.Context, _ string, m *proto.ProxyMapping, _ string) {
			sentMappings = append(sentMappings, m)
		})

	mgr.reconcile(ctx, "acct-1")

	require.Len(t, sentMappings, 1, "first synth must emit one mapping")
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, sentMappings[0].Type, "first synth is a Create")
	assert.Equal(t, "agent-net-svc-acct-1", sentMappings[0].Id, "stable account-scoped virtual service id")
	assert.Equal(t, "violet.eu.proxy.netbird.io", sentMappings[0].Domain, "domain comes from settings (subdomain.cluster)")

	mgr.reconcileMu.Lock()
	cached := mgr.reconcileCache["acct-1"]
	mgr.reconcileMu.Unlock()
	require.Len(t, cached, 1, "cache must hold the synth result for next diff")
}

func TestReconcile_NoChange_EmitsNothingExtra(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, mockProxy := newReconcileMgr(t, ctrl)
	provider := newReconcileTestProvider()
	policy := newReconcileTestPolicy(provider.ID, "grp-eng")

	// Two identical synth runs.
	mockStore.EXPECT().
		GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").
		Return(newReconcileTestSettings(), nil).Times(2)
	mockStore.EXPECT().
		GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "acct-1").
		Return([]*types.Provider{provider}, nil).Times(2)
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, "acct-1").
		Return([]*types.Policy{policy}, nil).Times(2)
	mockStore.EXPECT().
		GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, "acct-1").
		Return([]*types.Guardrail{}, nil).Times(2)
	mockProxy.EXPECT().GetOIDCValidationConfig().Return(proxy.OIDCValidationConfig{}).Times(2)

	createCalls := 0
	updateCalls := 0
	mockProxy.EXPECT().
		SendServiceUpdateToCluster(ctx, "acct-1", gomock.Any(), gomock.Any()).
		Do(func(_ context.Context, _ string, m *proto.ProxyMapping, _ string) {
			switch m.Type {
			case proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED:
				createCalls++
			case proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED:
				updateCalls++
			}
		}).
		AnyTimes()

	mgr.reconcile(ctx, "acct-1")
	mgr.reconcile(ctx, "acct-1")

	assert.Equal(t, 1, createCalls, "first reconcile creates")
	assert.Equal(t, 1, updateCalls, "second reconcile re-pushes as Modified (no semantic change but mapping fields refresh)")
}

func TestReconcile_PolicyRemoved_EmitsDelete(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, mockProxy := newReconcileMgr(t, ctrl)
	provider := newReconcileTestProvider()
	policy := newReconcileTestPolicy(provider.ID, "grp-eng")

	gomock.InOrder(
		// First reconcile: provider + policy, synthesised.
		mockStore.EXPECT().GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").Return(newReconcileTestSettings(), nil),
		mockStore.EXPECT().GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Provider{provider}, nil),
		mockStore.EXPECT().GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Policy{policy}, nil),
		mockStore.EXPECT().GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Guardrail{}, nil),
		// Second reconcile: policy gone, provider stays but no longer referenced.
		mockStore.EXPECT().GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").Return(newReconcileTestSettings(), nil),
		mockStore.EXPECT().GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Provider{provider}, nil),
		mockStore.EXPECT().GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Policy{}, nil),
	)
	mockProxy.EXPECT().GetOIDCValidationConfig().Return(proxy.OIDCValidationConfig{}).AnyTimes()

	var seenTypes []proto.ProxyMappingUpdateType
	mockProxy.EXPECT().
		SendServiceUpdateToCluster(ctx, "acct-1", gomock.Any(), "eu.proxy.netbird.io").
		Do(func(_ context.Context, _ string, m *proto.ProxyMapping, _ string) {
			seenTypes = append(seenTypes, m.Type)
		}).
		AnyTimes()

	mgr.reconcile(ctx, "acct-1")
	mgr.reconcile(ctx, "acct-1")

	require.Len(t, seenTypes, 2, "create then delete")
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, seenTypes[0])
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, seenTypes[1])

	mgr.reconcileMu.Lock()
	_, present := mgr.reconcileCache["acct-1"]
	mgr.reconcileMu.Unlock()
	assert.False(t, present, "cache for the account must be cleared once nothing is synthesised")
}

func TestReconcile_NilProxyController_NoOp(t *testing.T) {
	ctx := context.Background()
	mgr := &managerImpl{
		reconcileCache: make(map[string]map[string]*proto.ProxyMapping),
	}
	// Must not panic; must not query the store.
	mgr.reconcile(ctx, "acct-1")
}

func TestReconcile_EmptyAccountID_NoOp(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, _, _ := newReconcileMgr(t, ctrl)
	// Empty accountID short-circuits before any store call.
	mgr.reconcile(ctx, "")
}

func TestClusterFromMapping(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"simple", "openai.eu.proxy.netbird.io", "eu.proxy.netbird.io"},
		{"deeply nested", "a.b.c.d", "b.c.d"},
		{"no dot", "openai", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clusterFromMapping(&proto.ProxyMapping{Domain: tt.domain})
			assert.Equal(t, tt.want, got)
		})
	}
}
