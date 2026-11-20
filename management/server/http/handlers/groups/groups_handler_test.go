package groups

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/server"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

var TestPeers = map[string]*nbpeer.Peer{
	"A": {Key: "A", ID: "peer-A-ID", IP: netip.MustParseAddr("100.100.100.100")},
	"B": {Key: "B", ID: "peer-B-ID", IP: netip.MustParseAddr("200.200.200.200")},
}

func newPermissionsMock(t *testing.T, peersRead bool, err error) *permissions.MockManager {
	t.Helper()
	m := permissions.NewMockManager(gomock.NewController(t))
	m.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).
		Return(peersRead, context.Background(), err).
		AnyTimes()
	return m
}

func initGroupTestData(t *testing.T, initGroups ...*types.Group) *handler {
	return &handler{
		permissionsManager: newPermissionsMock(t, true, nil),
		accountManager: &mock_server.MockAccountManager{
			SaveGroupFunc: func(_ context.Context, accountID, userID string, group *types.Group, create bool) error {
				if !strings.HasPrefix(group.ID, "id-") {
					group.ID = "id-was-set"
				}
				return nil
			},
			GetGroupFunc: func(_ context.Context, _, groupID, _ string) (*types.Group, error) {
				groups := map[string]*types.Group{
					"id-jwt-group": {ID: "id-jwt-group", Name: "From JWT", Issued: types.GroupIssuedJWT},
					"id-existed":   {ID: "id-existed", Peers: []string{"A", "B"}, Issued: types.GroupIssuedAPI},
					"id-all":       {ID: "id-all", Name: "All", Issued: types.GroupIssuedAPI},
				}

				for _, group := range initGroups {
					groups[group.ID] = group
				}

				group, ok := groups[groupID]
				if !ok {
					return nil, status.Errorf(status.NotFound, "not found")
				}

				return group, nil
			},
			GetAllGroupsFunc: func(ctx context.Context, accountID, userID string) ([]*types.Group, error) {
				groups := []*types.Group{
					{ID: "id-jwt-group", Name: "From JWT", Issued: types.GroupIssuedJWT},
					{ID: "id-existed", Name: "Existed", Peers: []string{"A", "B"}, Issued: types.GroupIssuedAPI},
					{ID: "id-all", Name: "All", Issued: types.GroupIssuedAPI},
				}

				groups = append(groups, initGroups...)

				return groups, nil
			},
			GetGroupByNameFunc: func(ctx context.Context, groupName, _, _ string) (*types.Group, error) {
				if groupName == "All" {
					return &types.Group{ID: "id-all", Name: "All", Issued: types.GroupIssuedAPI}, nil
				}

				return nil, status.Errorf(status.NotFound, "unknown group name")
			},
			GetPeersFunc: func(ctx context.Context, accountID, userID, nameFilter, ipFilter, macFilter string) ([]*nbpeer.Peer, int, error) {
				return maps.Values(TestPeers), len(maps.Values(TestPeers)), nil
			},
			DeleteGroupFunc: func(_ context.Context, accountID, userId, groupID string) error {
				if groupID == "linked-grp" {
					err := &server.GroupLinkError{
						Resource: "something",
						Name:     "linked-grp",
					}
					var allErrors error
					return errors.Join(allErrors, err)
				}
				if groupID == "invalid-grp" {
					return fmt.Errorf("internal error")
				}
				return nil
			},
		},
	}
}

func TestGetGroup(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:           "getGroup OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/groups/idofthegroup",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "getGroup not found",
			requestType:    http.MethodGet,
			requestPath:    "/api/groups/notexists",
			expectedStatus: http.StatusNotFound,
		},
	}

	group := &types.Group{
		ID:   "idofthegroup",
		Name: "Group",
	}

	p := initGroupTestData(t, group)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "test_user",
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/groups/{groupId}", p.getGroup).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
				return
			}

			if !tc.expectedBody {
				return
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			got := &types.Group{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, got.ID, group.ID)
			assert.Equal(t, got.Name, group.Name)
		})
	}
}

func TestWriteGroup(t *testing.T) {
	groupIssuedAPI := "api"
	groupIssuedJWT := "jwt"
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		expectedGroup  *api.Group
		requestType    string
		requestPath    string
		requestBody    io.Reader
	}{
		{
			name:        "Write Group POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/groups",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"Default POSTed Group"}`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedGroup: &api.Group{
				Id:     "id-was-set",
				Name:   "Default POSTed Group",
				Issued: (*api.GroupIssued)(&groupIssuedAPI),
			},
		},
		{
			name:        "Write Group POST Invalid Name",
			requestType: http.MethodPost,
			requestPath: "/api/groups",
			requestBody: bytes.NewBuffer(
				[]byte(`{"name":""}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group POST Empty Resource",
			requestType: http.MethodPost,
			requestPath: "/api/groups",
			requestBody: bytes.NewBuffer(
				[]byte(`{"name":"With Resource","resources":[{}]}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group PUT Empty Resource",
			requestType: http.MethodPut,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"name":"With Resource","resources":[{"id":"","type":"host"}]}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group POST Unknown Resource Type",
			requestType: http.MethodPost,
			requestPath: "/api/groups",
			requestBody: bytes.NewBuffer(
				[]byte(`{"name":"With Resource","resources":[{"id":"res-1","type":"banana"}]}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group PUT OK",
			requestType: http.MethodPut,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"Default POSTed Group"}`)),
			expectedStatus: http.StatusOK,
			expectedGroup: &api.Group{
				Id:     "id-existed",
				Name:   "Default POSTed Group",
				Issued: (*api.GroupIssued)(&groupIssuedAPI),
			},
		},
		{
			name:        "Write Group PUT Invalid Name",
			requestType: http.MethodPut,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":""}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group PUT All Group Name",
			requestType: http.MethodPut,
			requestPath: "/api/groups/id-all",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"super"}`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group PUT not change Issue",
			requestType: http.MethodPut,
			requestPath: "/api/groups/id-jwt-group",
			requestBody: bytes.NewBuffer(
				[]byte(`{"Name":"changed","Issued":"api"}`)),
			expectedStatus: http.StatusOK,
			expectedGroup: &api.Group{
				Id:     "id-jwt-group",
				Name:   "changed",
				Issued: (*api.GroupIssued)(&groupIssuedJWT),
			},
		},
	}

	p := initGroupTestData(t)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "test_user",
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/groups", p.createGroup).Methods("POST")
			router.HandleFunc("/api/groups/{groupId}", p.updateGroup).Methods("PUT")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v, content: %s",
					status, tc.expectedStatus, string(content))
				return
			}

			if !tc.expectedBody {
				return
			}

			got := &api.Group{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}
			assert.Equal(t, got, tc.expectedGroup)
		})
	}
}

func TestGetAllGroups(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		expectedCount  int
	}{
		{
			name:           "Get All Groups",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/groups",
			expectedStatus: http.StatusOK,
			expectedCount:  3, // id-jwt-group, id-existed, id-all
		},
		{
			name:           "Get Group By Name - Existing",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/groups?name=All",
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:           "Get Group By Name - Not Found",
			expectedBody:   false,
			requestType:    http.MethodGet,
			requestPath:    "/api/groups?name=NonExistent",
			expectedStatus: http.StatusNotFound,
		},
	}

	p := initGroupTestData(t)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "test_user",
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/groups", p.getAllGroups).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
				return
			}

			if !tc.expectedBody {
				return
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			var groups []api.Group
			if err = json.Unmarshal(content, &groups); err != nil {
				t.Fatalf("Response is not in correct json format; %v", err)
			}

			assert.Equal(t, tc.expectedCount, len(groups))
		})
	}
}

func TestToGroupResponseSkipsEmptyResource(t *testing.T) {
	group := &types.Group{
		ID:        "id-resources",
		Name:      "Resources",
		Issued:    types.GroupIssuedAPI,
		Resources: []types.Resource{{}, {ID: "res-1", Type: types.ResourceTypeHost}},
	}

	got := toGroupResponse(peerVisibility{all: true}, group)

	assert.Equal(t, 1, got.ResourcesCount)
	assert.Equal(t, []api.Resource{{Id: "res-1", Type: api.ResourceType(types.ResourceTypeHost)}}, got.Resources)
}

func TestDeleteGroup(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
	}{
		{
			name:           "Try to delete linked group",
			requestType:    http.MethodDelete,
			requestPath:    "/api/groups/linked-grp",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   true,
		},
		{
			name:           "Try to cause internal error",
			requestType:    http.MethodDelete,
			requestPath:    "/api/groups/invalid-grp",
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   true,
		},
		{
			name:           "Try to cause internal error",
			requestType:    http.MethodDelete,
			requestPath:    "/api/groups/invalid-grp",
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   true,
		},
		{
			name:           "Delete group",
			requestType:    http.MethodDelete,
			requestPath:    "/api/groups/any-grp",
			expectedStatus: http.StatusOK,
			expectedBody:   false,
		},
	}

	p := initGroupTestData(t)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "test_user",
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})
			router := mux.NewRouter()
			router.HandleFunc("/api/groups/{groupId}", p.deleteGroup).Methods("DELETE")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v, content: %s",
					status, tc.expectedStatus, string(content))
				return
			}

			if tc.expectedBody {
				got := &util.ErrorResponse{}

				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
				assert.Equal(t, got.Code, tc.expectedStatus)
			}
		})
	}
}

func visibilityHandler(t *testing.T, peersRead bool, permErr error, ownPeers []*nbpeer.Peer, group *types.Group) *handler {
	t.Helper()
	return &handler{
		permissionsManager: newPermissionsMock(t, peersRead, permErr),
		accountManager: &mock_server.MockAccountManager{
			GetGroupFunc: func(_ context.Context, _, _, _ string) (*types.Group, error) {
				return group, nil
			},
			GetPeersFunc: func(_ context.Context, _, _, _, _, _ string) ([]*nbpeer.Peer, int, error) {
				return ownPeers, len(ownPeers), nil
			},
		},
	}
}

func getGroupVisibility(t *testing.T, h *handler) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/groups/grp", nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{UserId: "test_user", AccountId: "test_id"})

	router := mux.NewRouter()
	router.HandleFunc("/api/groups/{groupId}", h.getGroup).Methods("GET")
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestGetGroupPeerVisibility(t *testing.T) {
	group := &types.Group{ID: "grp", Name: "Group", Issued: types.GroupIssuedAPI, Peers: []string{"p1", "p2", "p3", "p1"}}

	t.Run("caller with peers read gets every member ID", func(t *testing.T) {
		h := visibilityHandler(t, true, nil, nil, group)

		recorder := getGroupVisibility(t, h)
		require.Equal(t, http.StatusOK, recorder.Code)

		got := &api.Group{}
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), got))
		assert.Equal(t, []string{"p1", "p2", "p3"}, got.Peers)
		assert.Equal(t, 3, got.PeersCount)
	})

	t.Run("caller without peers read gets only their own peers", func(t *testing.T) {
		own := []*nbpeer.Peer{{ID: "p2"}, {ID: "unrelated"}}
		h := visibilityHandler(t, false, nil, own, group)

		recorder := getGroupVisibility(t, h)
		require.Equal(t, http.StatusOK, recorder.Code)

		got := &api.Group{}
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), got))
		assert.Equal(t, []string{"p2"}, got.Peers)
		assert.Equal(t, 1, got.PeersCount)
	})

	t.Run("caller without peers read and no own peers gets none", func(t *testing.T) {
		h := visibilityHandler(t, false, nil, []*nbpeer.Peer{}, group)

		recorder := getGroupVisibility(t, h)
		require.Equal(t, http.StatusOK, recorder.Code)

		got := &api.Group{}
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), got))
		assert.Empty(t, got.Peers)
		assert.Equal(t, 0, got.PeersCount)
	})

	t.Run("permission check error denies and leaks no peers", func(t *testing.T) {
		h := visibilityHandler(t, false, errors.New("permission backend down"), []*nbpeer.Peer{{ID: "p1"}}, group)

		recorder := getGroupVisibility(t, h)
		assert.NotEqual(t, http.StatusOK, recorder.Code)
		assert.NotContains(t, recorder.Body.String(), "p1")
	})

	t.Run("fallback lookup error denies and leaks no peers", func(t *testing.T) {
		h := visibilityHandler(t, false, nil, nil, group)
		h.accountManager.(*mock_server.MockAccountManager).GetPeersFunc = func(_ context.Context, _, _, _, _, _ string) ([]*nbpeer.Peer, int, error) {
			return nil, 0, errors.New("store unavailable")
		}

		recorder := getGroupVisibility(t, h)
		assert.NotEqual(t, http.StatusOK, recorder.Code)
		assert.NotContains(t, recorder.Body.String(), "p1")
	})
}
