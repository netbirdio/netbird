package agentnetwork

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
)

func newModelDiscoveryManager(t *testing.T) (*managerImpl, *store.MockStore, *permissions.MockManager, *proxy.MockController) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockPermissions := permissions.NewMockManager(ctrl)
	mockProxy := proxy.NewMockController(ctrl)
	return &managerImpl{
		store:              mockStore,
		permissionsManager: mockPermissions,
		proxyController:    mockProxy,
		discoveryAttempts:  make(map[string]modelDiscoveryAttempt),
	}, mockStore, mockPermissions, mockProxy
}

func allowModelDiscovery(mockPermissions *permissions.MockManager) {
	mockPermissions.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "user-1", modules.AgentNetwork, operations.Update).
		Return(true, context.Background(), nil)
}

func TestDiscoverProviderModelsUsesPersistedProviderAndCluster(t *testing.T) {
	manager, mockStore, mockPermissions, mockProxy := newModelDiscoveryManager(t)
	allowModelDiscovery(mockPermissions)

	provider := &types.Provider{
		ID:                  "provider-1",
		AccountID:           "account-1",
		ProviderID:          "ollama",
		UpstreamURL:         "http://ollama.internal:11434/base",
		APIKey:              "stored-key",
		SkipTLSVerification: true,
	}
	mockStore.EXPECT().
		GetAgentNetworkProviderByID(gomock.Any(), store.LockingStrengthNone, "account-1", "provider-1").
		Return(provider, nil)
	mockStore.EXPECT().
		GetAgentNetworkSettings(gomock.Any(), store.LockingStrengthNone, "account-1").
		Return(&types.Settings{AccountID: "account-1", Cluster: "private.example.com"}, nil)
	mockProxy.EXPECT().
		DiscoverModels(gomock.Any(), "account-1", "private.example.com", gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _ string, request *proto.ModelDiscoveryRequest) (*proto.ModelDiscoveryResult, error) {
			assert.Empty(t, request.RequestId, "the control-plane server owns request IDs")
			assert.Equal(t, provider.UpstreamURL, request.UpstreamUrl)
			assert.Equal(t, "Authorization", request.AuthHeaderName)
			assert.Equal(t, "Bearer stored-key", request.AuthHeaderValue)
			assert.True(t, request.SkipTlsVerify)
			assert.True(t, request.OllamaFallback)
			return &proto.ModelDiscoveryResult{
				RequestId: "probe-123",
				Source:    "openai_v1_models",
				Models: []*proto.ModelDiscoveryModel{
					{Id: "zeta", Label: ""},
					{Id: "alpha", Label: "Alpha"},
					{Id: "zeta", Label: "duplicate"},
					{Id: "bad\x00model", Label: "bad"},
					{Id: strings.Repeat("x", maxDiscoveredModelLen+1), Label: "too long"},
				},
			}, nil
		})

	result, err := manager.DiscoverProviderModels(context.Background(), "account-1", "user-1", "provider-1")
	require.NoError(t, err)
	assert.Equal(t, "probe-123", result.RequestID)
	assert.Equal(t, "openai_v1_models", result.Source)
	assert.Equal(t, "private.example.com", result.ProxyCluster)
	assert.Equal(t, []types.DiscoveredModel{
		{ID: "alpha", Label: "Alpha"},
		{ID: "zeta", Label: "zeta"},
	}, result.Models)
}

func TestDiscoverProviderModelsRejectsUnsupportedProvider(t *testing.T) {
	manager, mockStore, mockPermissions, _ := newModelDiscoveryManager(t)
	allowModelDiscovery(mockPermissions)
	mockStore.EXPECT().
		GetAgentNetworkProviderByID(gomock.Any(), store.LockingStrengthNone, "account-1", "provider-1").
		Return(&types.Provider{
			ID:         "provider-1",
			AccountID:  "account-1",
			ProviderID: "openai_api",
		}, nil)

	_, err := manager.DiscoverProviderModels(context.Background(), "account-1", "user-1", "provider-1")
	require.Error(t, err)
	statusErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.PreconditionFailed, statusErr.Type())
	assert.Contains(t, err.Error(), "does not support")
}

func TestDiscoverProviderModelsPreservesCorrelatedProxyError(t *testing.T) {
	manager, mockStore, mockPermissions, mockProxy := newModelDiscoveryManager(t)
	allowModelDiscovery(mockPermissions)
	mockStore.EXPECT().
		GetAgentNetworkProviderByID(gomock.Any(), store.LockingStrengthNone, "account-1", "provider-1").
		Return(&types.Provider{
			ID:          "provider-1",
			AccountID:   "account-1",
			ProviderID:  "ollama",
			UpstreamURL: "http://ollama.internal:11434",
		}, nil)
	mockStore.EXPECT().
		GetAgentNetworkSettings(gomock.Any(), store.LockingStrengthNone, "account-1").
		Return(&types.Settings{AccountID: "account-1", Cluster: "private.example.com"}, nil)
	mockProxy.EXPECT().
		DiscoverModels(gomock.Any(), "account-1", "private.example.com", gomock.Any()).
		Return(&proto.ModelDiscoveryResult{
			RequestId: "probe-failed",
			Error:     "upstream returned HTTP 401",
		}, nil)

	_, err := manager.DiscoverProviderModels(context.Background(), "account-1", "user-1", "provider-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream returned HTTP 401")
	assert.Contains(t, err.Error(), "probe-failed")
}

func TestModelDiscoveryAdmissionControl(t *testing.T) {
	manager := &managerImpl{}
	start := time.Now()
	require.True(t, manager.beginModelDiscovery("account/provider", start))
	assert.False(t, manager.beginModelDiscovery("account/provider", start.Add(time.Second)))

	manager.finishModelDiscovery("account/provider")
	assert.False(t, manager.beginModelDiscovery("account/provider", start.Add(time.Second)))
	assert.True(t, manager.beginModelDiscovery("account/provider", start.Add(modelDiscoveryCooldown)))
}

func TestModelDiscoveryAdmissionControlExpiresFinishedAttempts(t *testing.T) {
	manager := &managerImpl{}
	start := time.Now()
	require.True(t, manager.beginModelDiscovery("account/provider", start))
	manager.finishModelDiscovery("account/provider")

	manager.expireModelDiscoveryAttempt("account/provider", start)

	manager.discoveryMu.Lock()
	_, retained := manager.discoveryAttempts["account/provider"]
	manager.discoveryMu.Unlock()
	assert.False(t, retained)
}

func TestModelDiscoveryAdmissionControlKeepsReplacementAttempt(t *testing.T) {
	manager := &managerImpl{}
	start := time.Now()
	require.True(t, manager.beginModelDiscovery("account/provider", start))
	manager.finishModelDiscovery("account/provider")
	require.True(t, manager.beginModelDiscovery("account/provider", start.Add(modelDiscoveryCooldown)))

	manager.expireModelDiscoveryAttempt("account/provider", start)

	manager.discoveryMu.Lock()
	attempt, retained := manager.discoveryAttempts["account/provider"]
	manager.discoveryMu.Unlock()
	require.True(t, retained)
	assert.True(t, attempt.inFlight)
	assert.Equal(t, start.Add(modelDiscoveryCooldown), attempt.lastStarted)
}
