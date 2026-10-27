package agentnetwork

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
)

func newReconcileMgr(t *testing.T, ctrl *gomock.Controller) (*managerImpl, *store.MockStore, *proxy.MockController) {
	t.Helper()
	mockStore := store.NewMockStore(ctrl)
	mockProxy := proxy.NewMockController(ctrl)
	return &managerImpl{
		store:           mockStore,
		proxyController: mockProxy,
		reconcileCache:  make(map[string]map[string]syntheticMapping),
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
		AccountID:    "acct-1",
		Domain:       "violet.eu.proxy.netbird.io",
		ProxyAddress: "eu.proxy.netbird.io",
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
		reconcileCache: make(map[string]map[string]syntheticMapping),
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

// TestDiffMappings_ServingProxyChange — when the proxy serving an account
// changes, the same service ID must be deleted on the old proxy and created on
// the new one. The cluster cannot be recovered from the mapping's domain: with a
// placement-free endpoint the domain does not change at all when the serving
// proxy does, so a domain-derived cluster sees no change and emits a plain
// update, addressed to a proxy that does not exist.
func TestDiffMappings_ServingProxyChange(t *testing.T) {
	previous := map[string]syntheticMapping{
		"svc-1": {
			mapping: &proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1", Domain: "brave-otter.gateway.example.com"},
			cluster: "proxy.example.com",
		},
	}
	current := map[string]syntheticMapping{
		"svc-1": {
			mapping: &proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1", Domain: "brave-otter.gateway.example.com"},
			cluster: "brave-otter.gateway.example.com",
		},
	}

	creates, updates, deletes := diffMappings(previous, current)

	if assert.Len(t, deletes, 1, "the old proxy must be told to drop the mapping") {
		assert.Equal(t, "proxy.example.com", deletes[0].cluster)
	}
	if assert.Len(t, creates, 1, "the new proxy must be told to add it") {
		assert.Equal(t, "brave-otter.gateway.example.com", creates[0].cluster)
	}
	assert.Empty(t, updates, "a serving-proxy move is a delete plus a create, not an update")
}

// TestDiffMappings_UnchangedClusterIsAnUpdate keeps the ordinary path: same
// service, same proxy, changed contents.
func TestDiffMappings_UnchangedClusterIsAnUpdate(t *testing.T) {
	previous := map[string]syntheticMapping{
		"svc-1": {
			mapping: &proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1", Domain: "otter.proxy.example.com"},
			cluster: "proxy.example.com",
		},
	}
	current := map[string]syntheticMapping{
		"svc-1": {
			mapping: &proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1", Domain: "otter.proxy.example.com"},
			cluster: "proxy.example.com",
		},
	}

	creates, updates, deletes := diffMappings(previous, current)

	assert.Empty(t, creates)
	assert.Empty(t, deletes)
	if assert.Len(t, updates, 1) {
		assert.Equal(t, "proxy.example.com", updates[0].cluster)
	}
}

// TestDiffMappings_RemovedServiceIsDeletedOnItsOwnCluster — a service that has
// gone away is deleted on the cluster it was last served by, which is recorded
// rather than re-derived.
func TestDiffMappings_RemovedServiceIsDeletedOnItsOwnCluster(t *testing.T) {
	previous := map[string]syntheticMapping{
		"svc-1": {
			mapping: &proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1", Domain: "brave-otter.gateway.example.com"},
			cluster: "brave-otter.gateway.example.com",
		},
	}

	creates, updates, deletes := diffMappings(previous, map[string]syntheticMapping{})

	assert.Empty(t, creates)
	assert.Empty(t, updates)
	if assert.Len(t, deletes, 1) {
		assert.Equal(t, "brave-otter.gateway.example.com", deletes[0].cluster)
	}
}

// TestRemoveAccountGateway_EmitsRemovedFromStore — account deletion runs on an
// instance that may never have reconciled the account, so its cache is empty.
// The mappings are synthesised from the store, still intact before the delete,
// and each is sent as REMOVED to the cluster that serves it.
func TestRemoveAccountGateway_EmitsRemovedFromStore(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, mockProxy := newReconcileMgr(t, ctrl)
	provider := newReconcileTestProvider()
	policy := newReconcileTestPolicy(provider.ID, "grp-eng")

	expectReconcileSynthInputs(mockStore, ctx, []*types.Provider{provider}, []*types.Policy{policy}, []*types.Guardrail{})
	mockProxy.EXPECT().GetOIDCValidationConfig().Return(proxy.OIDCValidationConfig{})

	var sent []*proto.ProxyMapping
	mockProxy.EXPECT().
		SendServiceUpdateToCluster(ctx, "acct-1", gomock.Any(), "eu.proxy.netbird.io").
		Do(func(_ context.Context, _ string, m *proto.ProxyMapping, _ string) {
			sent = append(sent, m)
		})

	require.NoError(t, mgr.RemoveAccountGateway(ctx, "acct-1"))

	require.Len(t, sent, 1, "the account's one gateway mapping must be removed")
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, sent[0].Type, "the update must be a removal")
	assert.Equal(t, "agent-net-svc-acct-1", sent[0].Id, "the removal must name the account's gateway service")
}

// TestRemoveAccountGateway_AlsoRemovesCachedMappings — a mapping this instance
// last sent but the store no longer synthesises (here, one on another cluster)
// is removed too, and the account's cache entry is cleared.
func TestRemoveAccountGateway_AlsoRemovesCachedMappings(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, mockProxy := newReconcileMgr(t, ctrl)
	mgr.reconcileCache["acct-1"] = map[string]syntheticMapping{
		"stale-svc": {mapping: &proto.ProxyMapping{Id: "stale-svc"}, cluster: "us.proxy.netbird.io"},
	}

	// Settings but no providers: the store synthesises nothing.
	mockStore.EXPECT().
		GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").
		Return(newReconcileTestSettings(), nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "acct-1").
		Return([]*types.Provider{}, nil)
	mockProxy.EXPECT().GetOIDCValidationConfig().Return(proxy.OIDCValidationConfig{})

	var sent []*proto.ProxyMapping
	mockProxy.EXPECT().
		SendServiceUpdateToCluster(ctx, "acct-1", gomock.Any(), "us.proxy.netbird.io").
		Do(func(_ context.Context, _ string, m *proto.ProxyMapping, _ string) {
			sent = append(sent, m)
		})

	require.NoError(t, mgr.RemoveAccountGateway(ctx, "acct-1"))

	require.Len(t, sent, 1, "the cached mapping must be removed from its own cluster")
	assert.Equal(t, "stale-svc", sent[0].Id)
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, sent[0].Type)
	mgr.reconcileMu.Lock()
	_, present := mgr.reconcileCache["acct-1"]
	mgr.reconcileMu.Unlock()
	assert.False(t, present, "the deleted account's cache entry must be cleared")
}

// TestRemoveAccountGateway_SynthFailureAbortsDeletion — if the mappings cannot
// be read, nothing is sent and the error is returned, which as an account
// deletion hook keeps the account rather than leaving its gateway running.
func TestRemoveAccountGateway_SynthFailureAbortsDeletion(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, _ := newReconcileMgr(t, ctrl)
	mockStore.EXPECT().
		GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").
		Return(nil, status.Errorf(status.Internal, "store unavailable"))

	assert.Error(t, mgr.RemoveAccountGateway(ctx, "acct-1"), "a failed synthesis must fail the hook")
}

func TestRemoveAccountGateway_NilProxyController_NoOp(t *testing.T) {
	mgr := &managerImpl{reconcileCache: make(map[string]map[string]syntheticMapping)}
	// Must not panic and must not query the store.
	assert.NoError(t, mgr.RemoveAccountGateway(context.Background(), "acct-1"))
}

// TestReconcile_ConcurrentWithGatewayChanges — while an account's gateway
// flaps (its policy is removed and re-added between reads), concurrent
// reconciles and RemoveAccountGateway share the cached mappings: one caches a
// mapping and sends it, another finds it gone and sends its removal. Run under
// -race: neither path may write a cached mapping, only copies of it.
func TestReconcile_ConcurrentWithGatewayChanges(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr, mockStore, mockProxy := newReconcileMgr(t, ctrl)
	// gomock serialises every call on the controller's mutex, which would give
	// the race detector the ordering the code under test lacks. The sends go
	// through a fake that takes no lock.
	mgr.proxyController = unsyncedSender{MockController: mockProxy}
	provider := newReconcileTestProvider()
	policy := newReconcileTestPolicy(provider.ID, "grp-eng")

	var reads atomic.Int64
	mockStore.EXPECT().GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "acct-1").Return(newReconcileTestSettings(), nil).AnyTimes()
	mockStore.EXPECT().GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Provider{provider}, nil).AnyTimes()
	mockStore.EXPECT().GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, "acct-1").
		DoAndReturn(func(context.Context, store.LockingStrength, string) ([]*types.Policy, error) {
			if reads.Add(1)%2 == 0 {
				return []*types.Policy{}, nil
			}
			return []*types.Policy{policy}, nil
		}).AnyTimes()
	mockStore.EXPECT().GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, "acct-1").Return([]*types.Guardrail{}, nil).AnyTimes()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(remove bool) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if remove && j%10 == 0 {
					_ = mgr.RemoveAccountGateway(ctx, "acct-1")
					continue
				}
				mgr.reconcile(ctx, "acct-1")
			}
		}(i == 0)
	}
	wg.Wait()
}

// unsyncedSender answers the calls reconcile makes on every pass without any
// locking, so concurrent callers are not ordered by the fake itself.
type unsyncedSender struct {
	*proxy.MockController
}

func (unsyncedSender) GetOIDCValidationConfig() proxy.OIDCValidationConfig {
	return proxy.OIDCValidationConfig{}
}

func (unsyncedSender) SendServiceUpdateToCluster(context.Context, string, *proto.ProxyMapping, string) {}
