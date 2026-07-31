package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type discoveryManagerStub struct {
	agentnetwork.Manager
	result     *agentNetworkTypes.ModelDiscoveryResult
	err        error
	accountID  string
	userID     string
	providerID string
}

func (m *discoveryManagerStub) DiscoverProviderModels(_ context.Context, accountID, userID, providerID string) (*agentNetworkTypes.ModelDiscoveryResult, error) {
	m.accountID = accountID
	m.userID = userID
	m.providerID = providerID
	return m.result, m.err
}

func TestDiscoverProviderModelsHandler(t *testing.T) {
	manager := &discoveryManagerStub{
		Manager: agentnetwork.NewManagerMock(),
		result: &agentNetworkTypes.ModelDiscoveryResult{
			RequestID:    "probe-123",
			Source:       "ollama_api_tags",
			ProxyCluster: "private.example.com",
			Models: []agentNetworkTypes.DiscoveredModel{
				{ID: "llama3.2:latest", Label: "llama3.2:latest"},
			},
		},
	}
	router := mux.NewRouter()
	RegisterEndpoints(manager, router)

	req := httptest.NewRequest(http.MethodPost, "/agent-network/providers/provider-1/discover-models", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    testUserID,
		AccountId: testAccountID,
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var response api.AgentNetworkModelDiscoveryResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, testAccountID, manager.accountID)
	assert.Equal(t, testUserID, manager.userID)
	assert.Equal(t, "provider-1", manager.providerID)
	assert.Equal(t, "probe-123", response.RequestId)
	assert.Equal(t, "private.example.com", response.ProxyCluster)
	assert.Equal(t, api.AgentNetworkModelDiscoveryResponseSourceOllamaApiTags, response.Source)
	require.Len(t, response.Models, 1)
	assert.Equal(t, "llama3.2:latest", response.Models[0].Id)
}
