package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type playgroundManagerStub struct {
	agentnetwork.Manager
	request  agentnetwork.PlaygroundRequest
	response *agentnetwork.PlaygroundResponse
	err      error
}

func (s *playgroundManagerStub) ExecutePlayground(
	_ context.Context,
	_, _ string,
	req agentnetwork.PlaygroundRequest,
) (*agentnetwork.PlaygroundResponse, error) {
	s.request = req
	return s.response, s.err
}

func TestPlaygroundHandlerPreservesNestedUpstreamResponse(t *testing.T) {
	manager := &playgroundManagerStub{
		response: &agentnetwork.PlaygroundResponse{
			StatusCode: http.StatusForbidden,
			Headers: []proxy.AgentNetworkPlaygroundHeader{
				{Name: "Content-Type", Values: []string{"application/octet-stream"}},
				{Name: "X-Empty", Values: []string{}},
			},
			Body:                []byte{0xff, 0x00},
			BodyTruncated:       true,
			UserID:              "user-1",
			GroupIDs:            []string{},
			GroupNames:          []string{},
			PolicyDecision:      "deny",
			PolicyReason:        "no_authorised_provider",
			AuthorisingGroupIDs: []string{},
		},
	}
	router := mux.NewRouter()
	RegisterEndpoints(manager, router)

	request := httptest.NewRequest(http.MethodPost, "/agent-network/playground", strings.NewReader(`{
		"principal":{"kind":"peer","id":"peer-1"},
		"method":"POST",
		"path":"/v1/chat/completions",
		"headers":[{"name":"Content-Type","values":["application/json"]}],
		"body":"{\"model\":\"gpt-4o\"}"
	}`))
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{UserId: testUserID, AccountId: testAccountID})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response api.AgentNetworkPlaygroundResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, http.StatusForbidden, response.StatusCode, "Upstream status should remain nested")
	assert.Equal(t, api.AgentNetworkPlaygroundResponseBodyEncodingBase64, response.BodyEncoding, "Binary body should be base64 encoded")
	assert.Equal(t, "/wA=", response.Body, "Body should preserve exact bytes")
	assert.True(t, response.BodyTruncated, "Truncation should be surfaced")
	require.Len(t, response.Headers, 2, "Response headers should be preserved")
	assert.NotNil(t, response.Headers[1].Values, "Empty header values should serialize as an array")
	assert.NotNil(t, response.Identity.GroupIds, "Empty group IDs should serialize as an array")
	assert.NotNil(t, response.Identity.GroupNames, "Empty group names should serialize as an array")
	assert.NotNil(t, response.Policy.AuthorisingGroupIds, "Empty authorising group IDs should serialize as an array")
	assert.Equal(t, proxy.PlaygroundPrincipalPeer, manager.request.Principal.Kind, "Principal kind should reach the manager")
	assert.Equal(t, "peer-1", manager.request.Principal.ID, "Peer ID should reach the manager")
	assert.Equal(t, `{"model":"gpt-4o"}`, string(manager.request.Body), "Provider body should remain native JSON")
}

func TestPlaygroundHandlerMapsUnavailableProxy(t *testing.T) {
	manager := &playgroundManagerStub{
		err: grpcstatus.Error(codes.Unavailable, "upgrade or connect a playground-capable proxy"),
	}
	router := mux.NewRouter()
	RegisterEndpoints(manager, router)
	request := httptest.NewRequest(http.MethodPost, "/agent-network/playground", strings.NewReader(`{
		"principal":{"kind":"group","id":"group-1"},
		"method":"GET",
		"path":"/v1/models",
		"headers":[],
		"body":""
	}`))
	request = nbcontext.SetUserAuthInRequest(request, auth.UserAuth{UserId: testUserID, AccountId: testAccountID})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "Unavailable proxy should be actionable")
	assert.Contains(t, recorder.Body.String(), "playground-capable proxy", "Response should explain the capability requirement")
}
