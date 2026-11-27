package v1alpha1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// TestGroupRoutesThroughValidatingMiddleware sends every group route through NewAPIV1Handler, so the
// embedded bundle must accept the path, method and body of each one.
func TestGroupRoutesThroughValidatingMiddleware(t *testing.T) {
	group := &types.Group{ID: "g1", Name: "devs", Issued: types.GroupIssuedAPI, Peers: []string{"peer-a"}}

	var batchCalls []string
	accountManager := &mock_server.MockAccountManager{
		GetAllGroupsFunc: func(context.Context, string, string) ([]*types.Group, error) {
			return []*types.Group{group}, nil
		},
		GetGroupFunc: func(context.Context, string, string, string) (*types.Group, error) {
			return group, nil
		},
		GetGroupByNameFunc: func(_ context.Context, name, _, _ string) (*types.Group, error) {
			if name == types.GroupAllName {
				return &types.Group{ID: "id-all", Name: types.GroupAllName}, nil
			}
			return group, nil
		},
		SaveGroupFunc:   func(context.Context, string, string, *types.Group, bool) error { return nil },
		DeleteGroupFunc: func(context.Context, string, string, string) error { return nil },
		AddPeersToGroupFunc: func(_ context.Context, _, _, _ string, peerIDs []string) (*types.Group, error) {
			batchCalls = append(batchCalls, "add:"+strings.Join(peerIDs, ","))
			return group, nil
		},
		RemovePeersFromGroupFunc: func(_ context.Context, _, _, _ string, peerIDs []string) (*types.Group, error) {
			batchCalls = append(batchCalls, "remove:"+strings.Join(peerIDs, ","))
			return group, nil
		},
	}

	permissionsManager := permissions.NewMockManager(gomock.NewController(t))
	permissionsManager.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(true, context.Background(), nil).
		AnyTimes()

	root := mux.NewRouter()
	_, err := NewAPIV1Handler(context.Background(), root.PathPrefix("/api/v1alpha1").Subrouter(), accountManager, nil, nil, permissionsManager)
	require.NoError(t, err)

	tt := []struct {
		name         string
		method       string
		path         string
		body         string
		expectedCode int
		expectedCall string
	}{
		{name: "list", method: http.MethodGet, path: "/groups", expectedCode: http.StatusOK},
		{name: "list filtered by name", method: http.MethodGet, path: "/groups?name=devs", expectedCode: http.StatusOK},
		{name: "create", method: http.MethodPost, path: "/groups", body: `{"name":"ops","peers":["peer-a"],"resources":[{"id":"r1","type":"host"}]}`, expectedCode: http.StatusOK},
		{name: "get", method: http.MethodGet, path: "/groups/g1", expectedCode: http.StatusOK},
		{name: "update", method: http.MethodPut, path: "/groups/g1", body: `{"name":"devs","peers":["peer-a"]}`, expectedCode: http.StatusOK},
		{name: "delete", method: http.MethodDelete, path: "/groups/g1", expectedCode: http.StatusOK},
		{name: "add peers", method: http.MethodPost, path: "/groups/g1/peers", body: `{"peer_ids":["peer-b","peer-c"]}`, expectedCode: http.StatusOK, expectedCall: "add:peer-b,peer-c"},
		{name: "remove peers with a delete body", method: http.MethodDelete, path: "/groups/g1/peers", body: `{"peer_ids":["peer-b"]}`, expectedCode: http.StatusOK, expectedCall: "remove:peer-b"},
		{name: "add peers rejects empty list", method: http.MethodPost, path: "/groups/g1/peers", body: `{"peer_ids":[]}`, expectedCode: http.StatusUnprocessableEntity},
		{name: "remove peers rejects missing body", method: http.MethodDelete, path: "/groups/g1/peers", expectedCode: http.StatusUnprocessableEntity},
		{name: "create rejects missing name", method: http.MethodPost, path: "/groups", body: `{"peers":[]}`, expectedCode: http.StatusUnprocessableEntity},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			batchCalls = nil

			req := httptest.NewRequest(tc.method, "/api/v1alpha1"+tc.path, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{UserId: "user", AccountId: "account", Domain: "example.com"})

			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectedCode, rec.Code, rec.Body.String())
			if tc.expectedCall == "" {
				assert.Empty(t, batchCalls)
				return
			}
			assert.Equal(t, []string{tc.expectedCall}, batchCalls, "the body must reach the handler intact")
		})
	}
}
