package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

func newTestRouter(t *testing.T) (*mux.Router, *exitnodes.MockManager) {
	t.Helper()
	mockManager := exitnodes.NewMockManager(gomock.NewController(t))
	router := mux.NewRouter()
	RegisterEndpoints(router.PathPrefix("/api").Subrouter(), mockManager)
	return router, mockManager
}

func doRequest(t *testing.T, router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: testAccountID, UserId: testUserID})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func apiTestExitNode() *exitnodes.ExitNode {
	return &exitnodes.ExitNode{
		ID:          "en1",
		AccountID:   testAccountID,
		PublicID:    "secret-public-id",
		Name:        "office",
		Description: "office uplink",
		Enabled:     true,
		RoutingPeers: []exitnodes.RoutingPeer{
			{ID: "rp1", PublicID: "secret-rp1-public", Peer: "p1", Metric: 10, Enabled: true},
			{ID: "rp2", PublicID: "secret-rp2-public", PeerGroups: []string{"pg1", "pg2"}, Metric: 20},
		},
		Masquerade: true,
		Groups:     []string{"dist"},
		AutoApply:  true,
	}
}

// The expected JSON is written out by hand: public IDs never appear, an unset
// peer or peer group list is omitted and empty lists are arrays, not null.
const apiTestExitNodeJSON = `{
	"id": "en1",
	"name": "office",
	"description": "office uplink",
	"enabled": true,
	"routing_peers": [
		{"id": "rp1", "peer": "p1", "metric": 10, "enabled": true},
		{"id": "rp2", "peer_groups": ["pg1", "pg2"], "metric": 20, "enabled": false}
	],
	"masquerade": true,
	"groups": ["dist"],
	"access_control_groups": [],
	"auto_apply": true
}`

func TestAPI_GetAllExitNodes(t *testing.T) {
	router, mockManager := newTestRouter(t)
	mockManager.EXPECT().GetAllExitNodes(gomock.Any(), testAccountID, testUserID).
		Return([]*exitnodes.ExitNode{apiTestExitNode()}, nil)

	rec := doRequest(t, router, http.MethodGet, "/api/exit-nodes", "")

	require.Equal(t, http.StatusOK, rec.Code, "status code, body: %s", rec.Body.String())
	assert.JSONEq(t, "["+apiTestExitNodeJSON+"]", rec.Body.String(), "response body")
}

func TestAPI_GetAllExitNodes_Empty(t *testing.T) {
	router, mockManager := newTestRouter(t)
	mockManager.EXPECT().GetAllExitNodes(gomock.Any(), testAccountID, testUserID).Return(nil, nil)

	rec := doRequest(t, router, http.MethodGet, "/api/exit-nodes", "")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, "[]", rec.Body.String(), "an account without exit nodes should get an empty array")
}

func TestAPI_GetExitNode(t *testing.T) {
	router, mockManager := newTestRouter(t)
	mockManager.EXPECT().GetExitNode(gomock.Any(), testAccountID, testUserID, "en1").Return(apiTestExitNode(), nil)

	rec := doRequest(t, router, http.MethodGet, "/api/exit-nodes/en1", "")

	require.Equal(t, http.StatusOK, rec.Code, "status code, body: %s", rec.Body.String())
	assert.JSONEq(t, apiTestExitNodeJSON, rec.Body.String(), "response body")
}

func TestAPI_CreateExitNode(t *testing.T) {
	router, mockManager := newTestRouter(t)
	body := `{
		"name": "office",
		"description": "office uplink",
		"enabled": true,
		"routing_peers": [
			{"id": "ignored-by-manager", "peer": "p1", "metric": 10, "enabled": true},
			{"peer_groups": ["pg1", "pg2"], "metric": 20, "enabled": false}
		],
		"masquerade": true,
		"groups": ["dist"],
		"access_control_groups": ["acl"],
		"auto_apply": true
	}`

	mockManager.EXPECT().CreateExitNode(gomock.Any(), testAccountID, testUserID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _ string, input *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
			assert.Equal(t, &exitnodes.ExitNode{
				Name:        "office",
				Description: "office uplink",
				Enabled:     true,
				RoutingPeers: []exitnodes.RoutingPeer{
					{ID: "ignored-by-manager", Peer: "p1", Metric: 10, Enabled: true},
					{PeerGroups: []string{"pg1", "pg2"}, Metric: 20},
				},
				Masquerade:          true,
				Groups:              []string{"dist"},
				AccessControlGroups: []string{"acl"},
				AutoApply:           true,
			}, input, "the request should map onto the exit node")
			return apiTestExitNode(), nil
		})

	rec := doRequest(t, router, http.MethodPost, "/api/exit-nodes", body)

	require.Equal(t, http.StatusOK, rec.Code, "status code, body: %s", rec.Body.String())
	assert.JSONEq(t, apiTestExitNodeJSON, rec.Body.String(), "response body")
}

func TestAPI_CreateExitNode_OptionalFieldsOmitted(t *testing.T) {
	router, mockManager := newTestRouter(t)
	body := `{"name": "office", "enabled": false, "routing_peers": [{"peer": "p1", "metric": 1, "enabled": true}],
		"masquerade": false, "groups": ["dist"], "auto_apply": false}`

	mockManager.EXPECT().CreateExitNode(gomock.Any(), testAccountID, testUserID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _ string, input *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
			assert.Empty(t, input.Description, "description")
			assert.Nil(t, input.AccessControlGroups, "access control groups")
			assert.Equal(t, []exitnodes.RoutingPeer{{Peer: "p1", Metric: 1, Enabled: true}}, input.RoutingPeers, "routing peers")
			return apiTestExitNode(), nil
		})

	rec := doRequest(t, router, http.MethodPost, "/api/exit-nodes", body)
	assert.Equal(t, http.StatusOK, rec.Code, "status code, body: %s", rec.Body.String())
}

func TestAPI_UpdateExitNode(t *testing.T) {
	router, mockManager := newTestRouter(t)
	body := `{
		"name": "office",
		"enabled": true,
		"routing_peers": [{"id": "rp1", "peer": "p1", "metric": 10, "enabled": true}],
		"masquerade": true,
		"groups": ["dist"],
		"auto_apply": true
	}`

	mockManager.EXPECT().UpdateExitNode(gomock.Any(), testAccountID, testUserID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _ string, input *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
			assert.Equal(t, "en1", input.ID, "the path parameter should select the exit node")
			assert.Equal(t, []exitnodes.RoutingPeer{{ID: "rp1", Peer: "p1", Metric: 10, Enabled: true}}, input.RoutingPeers,
				"the routing peer id should be passed through so the entry keeps its identity")
			return apiTestExitNode(), nil
		})

	rec := doRequest(t, router, http.MethodPut, "/api/exit-nodes/en1", body)

	require.Equal(t, http.StatusOK, rec.Code, "status code, body: %s", rec.Body.String())
	assert.JSONEq(t, apiTestExitNodeJSON, rec.Body.String(), "response body")
}

func TestAPI_DeleteExitNode(t *testing.T) {
	router, mockManager := newTestRouter(t)
	mockManager.EXPECT().DeleteExitNode(gomock.Any(), testAccountID, testUserID, "en1").Return(nil)

	rec := doRequest(t, router, http.MethodDelete, "/api/exit-nodes/en1", "")

	require.Equal(t, http.StatusOK, rec.Code, "status code, body: %s", rec.Body.String())
	assert.JSONEq(t, "{}", rec.Body.String(), "delete should return an empty object")
}

func TestAPI_InvalidJSON(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/exit-nodes"},
		{http.MethodPut, "/api/exit-nodes/en1"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			router, _ := newTestRouter(t)

			// No manager expectation: a body that does not parse must not reach it.
			rec := doRequest(t, router, tc.method, tc.path, `{"name": `)
			assert.Equal(t, http.StatusBadRequest, rec.Code, "status code")
		})
	}
}

func TestAPI_ManagerErrorsMapToStatusCodes(t *testing.T) {
	validBody := `{"name": "office", "enabled": true, "routing_peers": [{"peer": "p1", "metric": 1, "enabled": true}],
		"masquerade": true, "groups": ["dist"], "auto_apply": true}`

	tests := []struct {
		name     string
		method   string
		path     string
		body     string
		expect   func(m *exitnodes.MockManager, err error)
		err      error
		wantCode int
	}{
		{
			name:   "list permission denied",
			method: http.MethodGet, path: "/api/exit-nodes",
			expect: func(m *exitnodes.MockManager, err error) {
				m.EXPECT().GetAllExitNodes(gomock.Any(), testAccountID, testUserID).Return(nil, err)
			},
			err:      status.NewPermissionDeniedError(),
			wantCode: http.StatusForbidden,
		},
		{
			name:   "get not found",
			method: http.MethodGet, path: "/api/exit-nodes/missing",
			expect: func(m *exitnodes.MockManager, err error) {
				m.EXPECT().GetExitNode(gomock.Any(), testAccountID, testUserID, "missing").Return(nil, err)
			},
			err:      status.Errorf(status.NotFound, "exit node missing not found"),
			wantCode: http.StatusNotFound,
		},
		{
			name:   "create invalid",
			method: http.MethodPost, path: "/api/exit-nodes", body: validBody,
			expect: func(m *exitnodes.MockManager, err error) {
				m.EXPECT().CreateExitNode(gomock.Any(), testAccountID, testUserID, gomock.Any()).Return(nil, err)
			},
			err:      status.Errorf(status.InvalidArgument, "name should not end with \"-v6\""),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:   "create conflict",
			method: http.MethodPost, path: "/api/exit-nodes", body: validBody,
			expect: func(m *exitnodes.MockManager, err error) {
				m.EXPECT().CreateExitNode(gomock.Any(), testAccountID, testUserID, gomock.Any()).Return(nil, err)
			},
			err:      status.Errorf(status.AlreadyExists, "exit node with name \"office\" already exists"),
			wantCode: http.StatusConflict,
		},
		{
			name:   "update not found",
			method: http.MethodPut, path: "/api/exit-nodes/missing", body: validBody,
			expect: func(m *exitnodes.MockManager, err error) {
				m.EXPECT().UpdateExitNode(gomock.Any(), testAccountID, testUserID, gomock.Any()).Return(nil, err)
			},
			err:      status.Errorf(status.NotFound, "exit node missing not found"),
			wantCode: http.StatusNotFound,
		},
		{
			name:   "delete not found",
			method: http.MethodDelete, path: "/api/exit-nodes/missing",
			expect: func(m *exitnodes.MockManager, err error) {
				m.EXPECT().DeleteExitNode(gomock.Any(), testAccountID, testUserID, "missing").Return(err)
			},
			err:      status.Errorf(status.NotFound, "exit node missing not found"),
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, mockManager := newTestRouter(t)
			tt.expect(mockManager, tt.err)

			rec := doRequest(t, router, tt.method, tt.path, tt.body)

			require.Equal(t, tt.wantCode, rec.Code, "status code, body: %s", rec.Body.String())
			var resp struct {
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			sErr, ok := status.FromError(tt.err)
			require.True(t, ok)
			assert.Equal(t, sErr.Message, resp.Message, "the error message should reach the caller")
		})
	}
}

// The response type must not grow fields that leak internal identifiers.
func TestAPI_ResponseHasNoPublicIDs(t *testing.T) {
	raw, err := json.Marshal(apiTestExitNode().ToAPIResponse())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "secret", "public IDs must not be exposed")

	var decoded api.ExitNode
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, "en1", decoded.Id)
}
