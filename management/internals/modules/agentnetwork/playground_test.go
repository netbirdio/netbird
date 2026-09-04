package agentnetwork

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	agenttypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	servertypes "github.com/netbirdio/netbird/management/server/types"
)

func TestExecutePlaygroundRequiresProviderCreateBeforeDispatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "operator-1", modules.AgentNetworkProviders, operations.Create).
		Return(false, context.Background(), nil)

	manager := &managerImpl{permissionsManager: perms}
	_, err := manager.ExecutePlayground(context.Background(), "account-1", "operator-1", PlaygroundRequest{
		Principal: PlaygroundPrincipal{Kind: proxy.PlaygroundPrincipalGroup, ID: "group-1"},
		Method:    http.MethodGet,
		Path:      "/v1/models",
	})

	assert.Error(t, err, "Provider Create permission should gate live credential spending")
}

func TestExecutePlaygroundScopesSyntheticGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)
	mockStore := store.NewMockStore(ctrl)
	controller := proxy.NewMockController(ctrl)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "operator-1", modules.AgentNetworkProviders, operations.Create).
		Return(true, context.Background(), nil)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "operator-1", modules.Groups, operations.Read).
		Return(true, context.Background(), nil)
	mockStore.EXPECT().
		GetAgentNetworkSettings(gomock.Any(), store.LockingStrengthNone, "account-1").
		Return(&agenttypes.Settings{AccountID: "account-1", Domain: "agent.example.com", ProxyAddress: "proxy.example.com"}, nil)
	mockStore.EXPECT().
		GetGroupByID(gomock.Any(), store.LockingStrengthNone, "account-1", "group-1").
		Return(&servertypes.Group{ID: "group-1", AccountID: "account-1", Name: "Engineering"}, nil)
	controller.EXPECT().
		ExecuteAgentNetworkPlayground(gomock.Any(), "proxy.example.com", gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, command proxy.AgentNetworkPlaygroundRequest) (*proxy.AgentNetworkPlaygroundResponse, error) {
			assert.Equal(t, proxy.PlaygroundPrincipalGroup, command.PrincipalKind, "Command should retain synthetic group mode")
			assert.Equal(t, "group-1", command.PrincipalID, "Command should carry only the scoped group ID")
			assert.Empty(t, command.UserID, "Synthetic group mode should omit user identity")
			assert.Equal(t, []string{"group-1"}, command.GroupIDs, "Command should contain exactly the selected group")
			assert.Equal(t, []string{"Engineering"}, command.GroupNames, "Group name should pair with its ID")
			assert.NotEmpty(t, command.RequestID, "Dispatch should have a correlation ID")
			return &proxy.AgentNetworkPlaygroundResponse{StatusCode: http.StatusOK}, nil
		})

	manager := &managerImpl{store: mockStore, permissionsManager: perms, proxyController: controller}
	result, err := manager.ExecutePlayground(context.Background(), "account-1", "operator-1", PlaygroundRequest{
		Principal: PlaygroundPrincipal{Kind: proxy.PlaygroundPrincipalGroup, ID: "group-1"},
		Method:    http.MethodPost,
		Path:      "/v1/chat/completions",
		Headers:   []proxy.AgentNetworkPlaygroundHeader{{Name: "Content-Type", Values: []string{"application/json"}}},
		Body:      []byte(`{"model":"gpt-4o"}`),
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode, "Controller response should pass through")
}

func TestExecutePlaygroundResolvesPeerIdentity(t *testing.T) {
	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)
	mockStore := store.NewMockStore(ctrl)
	controller := proxy.NewMockController(ctrl)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "operator-1", modules.AgentNetworkProviders, operations.Create).
		Return(true, context.Background(), nil)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "operator-1", modules.Peers, operations.Read).
		Return(true, context.Background(), nil)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), "account-1", "operator-1", modules.Users, operations.Read).
		Return(true, context.Background(), nil)
	mockStore.EXPECT().
		GetAgentNetworkSettings(gomock.Any(), store.LockingStrengthNone, "account-1").
		Return(&agenttypes.Settings{
			AccountID:    "account-1",
			Domain:       "agent.example.com",
			ProxyAddress: "proxy.example.com",
		}, nil)
	mockStore.EXPECT().
		GetPeerByID(gomock.Any(), store.LockingStrengthNone, "account-1", "peer-1").
		Return(&nbpeer.Peer{
			ID:        "peer-1",
			AccountID: "account-1",
			Name:      "workstation",
			UserID:    "user-1",
		}, nil)
	mockStore.EXPECT().
		GetPeerGroups(gomock.Any(), store.LockingStrengthNone, "account-1", "peer-1").
		Return([]*servertypes.Group{{
			ID:        "group-1",
			AccountID: "account-1",
			Name:      "Engineering",
		}}, nil)
	mockStore.EXPECT().
		GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "user-1").
		Return(&servertypes.User{
			Id:        "user-1",
			AccountID: "account-1",
			Email:     "owner@example.com",
		}, nil)
	controller.EXPECT().
		ExecuteAgentNetworkPlayground(gomock.Any(), "proxy.example.com", gomock.Any()).
		DoAndReturn(func(
			_ context.Context,
			_ string,
			command proxy.AgentNetworkPlaygroundRequest,
		) (*proxy.AgentNetworkPlaygroundResponse, error) {
			assert.Equal(t, proxy.PlaygroundPrincipalPeer, command.PrincipalKind, "Command should retain peer mode")
			assert.Equal(t, "peer-1", command.PrincipalID, "Command should identify the selected peer")
			assert.Equal(t, "user-1", command.UserID, "Linked peer should resolve to its owner")
			assert.Equal(t, "owner@example.com", command.UserEmail, "Stored owner email should be forwarded")
			assert.Equal(t, []string{"group-1"}, command.GroupIDs, "Current peer groups should be forwarded")
			assert.Equal(t, []string{"Engineering"}, command.GroupNames, "Group name should pair with its ID")
			return &proxy.AgentNetworkPlaygroundResponse{StatusCode: http.StatusOK}, nil
		})

	manager := &managerImpl{
		store:              mockStore,
		permissionsManager: perms,
		proxyController:    controller,
	}
	result, err := manager.ExecutePlayground(
		context.Background(),
		"account-1",
		"operator-1",
		PlaygroundRequest{
			Principal: PlaygroundPrincipal{
				Kind: proxy.PlaygroundPrincipalPeer,
				ID:   "peer-1",
			},
			Method: http.MethodGet,
			Path:   "/v1/models",
		},
	)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode, "Controller response should pass through")
}
