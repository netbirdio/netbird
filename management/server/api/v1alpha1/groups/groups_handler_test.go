package groups

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/integration_reference"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "test-account"
	testUserID    = "test-user"
	allGroupID    = "id-all"
)

// testOptions configures who the caller is and how peer visibility resolves.
type testOptions struct {
	// readAllPeers is the answer of the peers read permission check.
	readAllPeers bool
	// permissionErr makes the peers read permission check fail.
	permissionErr error
	// ownPeers are the peers GetPeers returns for a caller without peers read permission.
	ownPeers []string
	// getPeersErr makes GetPeers fail.
	getPeersErr error
}

// testHandler is a groups handler over a mock account manager that records what it was asked to do.
type testHandler struct {
	*Handler
	saved       *types.Group
	savedCreate bool
	deleted     string
}

func newTestHandler(t *testing.T, opts testOptions, stored ...*types.Group) *testHandler {
	t.Helper()

	groups := map[string]*types.Group{
		allGroupID: {ID: allGroupID, Name: types.GroupAllName, Issued: types.GroupIssuedAPI, Peers: []string{"peer-a", "peer-b", "peer-c"}},
	}
	for _, g := range stored {
		groups[g.ID] = g
	}

	permissionsManager := permissions.NewMockManager(gomock.NewController(t))
	permissionsManager.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Eq(modules.Peers), gomock.Eq(operations.Read)).
		Return(opts.readAllPeers, context.Background(), opts.permissionErr).
		AnyTimes()

	th := &testHandler{}
	th.Handler = NewHandler(&mock_server.MockAccountManager{
		GetGroupFunc: func(_ context.Context, _, groupID, _ string) (*types.Group, error) {
			group, ok := groups[groupID]
			if !ok {
				return nil, status.NewGroupNotFoundError(groupID)
			}
			return group, nil
		},
		GetAllGroupsFunc: func(context.Context, string, string) ([]*types.Group, error) {
			result := make([]*types.Group, 0, len(groups))
			for _, g := range groups {
				result = append(result, g)
			}
			return result, nil
		},
		GetGroupByNameFunc: func(_ context.Context, name, _, _ string) (*types.Group, error) {
			for _, g := range groups {
				if g.Name == name {
					return g, nil
				}
			}
			return nil, status.Errorf(status.NotFound, "unknown group name")
		},
		GetPeersFunc: func(context.Context, string, string, string, string, string) ([]*nbpeer.Peer, int, error) {
			if opts.getPeersErr != nil {
				return nil, 0, opts.getPeersErr
			}
			peers := make([]*nbpeer.Peer, 0, len(opts.ownPeers))
			for _, id := range opts.ownPeers {
				peers = append(peers, &nbpeer.Peer{ID: id})
			}
			return peers, len(peers), nil
		},
		SaveGroupFunc: func(_ context.Context, _, _ string, group *types.Group, create bool) error {
			if create && group.Name == "taken" {
				return status.Errorf(status.AlreadyExists, "group with name %s already exists", group.Name)
			}
			if create {
				group.ID = "new-group-id"
			}
			th.saved, th.savedCreate = group, create
			return nil
		},
		DeleteGroupFunc: func(_ context.Context, _, _, groupID string) error {
			switch groupID {
			case "linked":
				return errors.Join(&linkError{})
			case "missing":
				return errors.Join(status.NewGroupNotFoundError(groupID))
			}
			th.deleted = groupID
			return nil
		},
	}, permissionsManager)

	return th
}

type linkError struct{}

func (*linkError) Error() string { return "group has been linked to something" }

var (
	validatorOnce sync.Once
	validator     *apiv1alpha1.V1ValidatorMiddleware
	validatorErr  error
)

// testValidator builds the spec validator once, since parsing the bundle dominates the test time.
func testValidator(t *testing.T) *apiv1alpha1.V1ValidatorMiddleware {
	t.Helper()
	validatorOnce.Do(func() {
		validator, validatorErr = apiv1alpha1.CreateV1ApiValidatingMiddleware()
	})
	require.NoError(t, validatorErr)
	return validator
}

func (th *testHandler) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	router := mux.NewRouter()
	router.Use(testValidator(t).Handler)
	th.WithEndpointsForRouter(router)

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{UserId: testUserID, AccountId: testAccountID, Domain: "example.com"})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeGroup(t *testing.T, rec *httptest.ResponseRecorder) apiv1alpha1.Group {
	t.Helper()
	var group apiv1alpha1.Group
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &group), "body: %s", rec.Body.String())
	return group
}

func apiGroup(id, name string, peers ...string) *types.Group {
	return &types.Group{ID: id, Name: name, Issued: types.GroupIssuedAPI, Peers: peers}
}

func TestGetGroup(t *testing.T) {
	stored := &types.Group{
		ID:        "g1",
		Name:      "devs",
		Issued:    types.GroupIssuedAPI,
		Peers:     []string{"peer-a", "peer-b", "peer-a"},
		Resources: []types.Resource{{ID: "res-1", Type: types.ResourceTypeHost}, {}},
	}

	t.Run("returns peer ids, deduplicated, with counts", func(t *testing.T) {
		rec := newTestHandler(t, testOptions{readAllPeers: true}, stored).do(t, http.MethodGet, "/groups/g1", "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		group := decodeGroup(t, rec)
		assert.Equal(t, "g1", group.Id)
		assert.Equal(t, "devs", group.Name)
		assert.Equal(t, []string{"peer-a", "peer-b"}, group.Peers)
		assert.Equal(t, 2, group.PeersCount, "peers_count is the number of returned IDs")
		assert.Equal(t, []apiv1alpha1.Resource{{Id: "res-1", Type: apiv1alpha1.ResourceTypeHost}}, group.Resources, "empty resources are skipped")
		assert.Equal(t, 1, group.ResourcesCount)
		require.NotNil(t, group.Issued)
		assert.Equal(t, apiv1alpha1.GroupMinimumIssuedAPI, *group.Issued)
	})

	t.Run("empty group serializes arrays, not null", func(t *testing.T) {
		rec := newTestHandler(t, testOptions{readAllPeers: true}, apiGroup("empty", "empty")).do(t, http.MethodGet, "/groups/empty", "")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"peers":[]`)
		assert.Contains(t, rec.Body.String(), `"resources":[]`)
	})

	t.Run("not found", func(t *testing.T) {
		rec := newTestHandler(t, testOptions{readAllPeers: true}).do(t, http.MethodGet, "/groups/nope", "")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestPeerVisibility(t *testing.T) {
	stored := apiGroup("g1", "devs", "peer-a", "peer-b", "peer-c")

	tt := []struct {
		name          string
		opts          testOptions
		expectedCode  int
		expectedPeers []string
	}{
		{
			name:          "peers read permission sees every member",
			opts:          testOptions{readAllPeers: true, getPeersErr: errors.New("must not be called")},
			expectedCode:  http.StatusOK,
			expectedPeers: []string{"peer-a", "peer-b", "peer-c"},
		},
		{
			name:          "without peers read permission only own peers are visible",
			opts:          testOptions{ownPeers: []string{"peer-b", "not-a-member"}},
			expectedCode:  http.StatusOK,
			expectedPeers: []string{"peer-b"},
		},
		{
			name:          "no own peers shows no members",
			opts:          testOptions{},
			expectedCode:  http.StatusOK,
			expectedPeers: []string{},
		},
		{
			name:         "permission check error denies",
			opts:         testOptions{readAllPeers: true, permissionErr: errors.New("boom")},
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "own peers lookup error denies",
			opts:         testOptions{getPeersErr: status.Errorf(status.Internal, "boom")},
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{"/groups/g1", "/groups?name=devs", "/groups"} {
				rec := newTestHandler(t, tc.opts, stored).do(t, http.MethodGet, path, "")
				require.Equal(t, tc.expectedCode, rec.Code, "%s: %s", path, rec.Body.String())
				if tc.expectedCode != http.StatusOK {
					assert.NotContains(t, rec.Body.String(), "peer-", "%s must not leak members on error", path)
					continue
				}

				var found *apiv1alpha1.Group
				if path == "/groups/g1" {
					g := decodeGroup(t, rec)
					found = &g
				} else {
					var groups []apiv1alpha1.Group
					require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &groups))
					for i := range groups {
						if groups[i].Id == "g1" {
							found = &groups[i]
						}
					}
				}
				require.NotNil(t, found, "%s should return g1", path)
				assert.Equal(t, tc.expectedPeers, found.Peers, path)
				assert.Equal(t, len(tc.expectedPeers), found.PeersCount, path)
			}
		})
	}
}

func TestGetAllGroups(t *testing.T) {
	th := newTestHandler(t, testOptions{readAllPeers: true}, apiGroup("g1", "devs", "peer-a"))

	rec := th.do(t, http.MethodGet, "/groups", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var groups []apiv1alpha1.Group
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &groups))
	assert.Len(t, groups, 2, "all groups are returned in one unpaginated array")

	rec = th.do(t, http.MethodGet, "/groups?name=devs", "")
	require.Equal(t, http.StatusOK, rec.Code)
	groups = nil
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &groups))
	require.Len(t, groups, 1, "name filter returns the matching group as a one element array")
	assert.Equal(t, "g1", groups[0].Id)

	rec = th.do(t, http.MethodGet, "/groups?name=unknown", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCreateGroup(t *testing.T) {
	t.Run("creates an api group", func(t *testing.T) {
		th := newTestHandler(t, testOptions{readAllPeers: true})
		rec := th.do(t, http.MethodPost, "/groups", `{"name":"devs","peers":["peer-a"],"resources":[{"id":"res-1","type":"host"}]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		require.NotNil(t, th.saved)
		assert.True(t, th.savedCreate)
		assert.Equal(t, types.GroupIssuedAPI, th.saved.Issued)
		assert.Equal(t, []string{"peer-a"}, th.saved.Peers)
		assert.Equal(t, []types.Resource{{ID: "res-1", Type: types.ResourceTypeHost}}, th.saved.Resources)

		group := decodeGroup(t, rec)
		assert.Equal(t, "new-group-id", group.Id)
		assert.Equal(t, []string{"peer-a"}, group.Peers)
	})

	t.Run("name only", func(t *testing.T) {
		th := newTestHandler(t, testOptions{readAllPeers: true})
		rec := th.do(t, http.MethodPost, "/groups", `{"name":"devs"}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{}, th.saved.Peers)
	})

	tt := []struct {
		name string
		body string
		code int
	}{
		{"empty name", `{"name":""}`, http.StatusUnprocessableEntity},
		{"missing name", `{"peers":[]}`, http.StatusUnprocessableEntity},
		{"invalid resource type", `{"name":"devs","resources":[{"id":"r","type":"bogus"}]}`, http.StatusUnprocessableEntity},
		{"empty resource id", `{"name":"devs","resources":[{"id":"","type":"host"}]}`, http.StatusUnprocessableEntity},
		{"malformed json", `{"name":`, http.StatusUnprocessableEntity},
		{"duplicate name", `{"name":"taken"}`, http.StatusConflict},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			th := newTestHandler(t, testOptions{readAllPeers: true})
			rec := th.do(t, http.MethodPost, "/groups", tc.body)
			assert.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Nil(t, th.saved, "a rejected request must not save")
		})
	}
}

func TestUpdateGroup(t *testing.T) {
	jwtGroup := &types.Group{
		ID:                   "id-jwt",
		Name:                 "from jwt",
		Issued:               types.GroupIssuedJWT,
		IntegrationReference: integration_reference.IntegrationReference{ID: 3, IntegrationType: "okta"},
	}

	t.Run("replaces members and keeps issued and integration reference", func(t *testing.T) {
		th := newTestHandler(t, testOptions{readAllPeers: true}, jwtGroup)
		rec := th.do(t, http.MethodPut, "/groups/id-jwt", `{"name":"renamed","peers":["peer-a","peer-b"]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		require.NotNil(t, th.saved)
		assert.False(t, th.savedCreate)
		assert.Equal(t, "id-jwt", th.saved.ID)
		assert.Equal(t, "renamed", th.saved.Name)
		assert.Equal(t, types.GroupIssuedJWT, th.saved.Issued)
		assert.Equal(t, jwtGroup.IntegrationReference, th.saved.IntegrationReference)

		group := decodeGroup(t, rec)
		assert.Equal(t, []string{"peer-a", "peer-b"}, group.Peers)
		require.NotNil(t, group.Issued)
		assert.Equal(t, apiv1alpha1.GroupMinimumIssuedJWT, *group.Issued)
	})

	t.Run("absent peers clears members", func(t *testing.T) {
		th := newTestHandler(t, testOptions{readAllPeers: true}, apiGroup("g1", "devs", "peer-a"))
		rec := th.do(t, http.MethodPut, "/groups/g1", `{"name":"devs"}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{}, th.saved.Peers)
	})

	t.Run("response honors peer visibility", func(t *testing.T) {
		th := newTestHandler(t, testOptions{ownPeers: []string{"peer-a"}}, apiGroup("g1", "devs"))
		rec := th.do(t, http.MethodPut, "/groups/g1", `{"name":"devs","peers":["peer-a","peer-b"]}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{"peer-a"}, decodeGroup(t, rec).Peers)
	})

	tt := []struct {
		name string
		path string
		body string
		code int
	}{
		{"all group is refused", "/groups/" + allGroupID, `{"name":"All"}`, http.StatusUnprocessableEntity},
		{"unknown group", "/groups/nope", `{"name":"x"}`, http.StatusNotFound},
		{"empty name", "/groups/g1", `{"name":""}`, http.StatusUnprocessableEntity},
		{"invalid resource", "/groups/g1", `{"name":"x","resources":[{"id":"r","type":"bogus"}]}`, http.StatusUnprocessableEntity},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			th := newTestHandler(t, testOptions{readAllPeers: true}, apiGroup("g1", "devs"))
			rec := th.do(t, http.MethodPut, tc.path, tc.body)
			assert.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Nil(t, th.saved, "a rejected request must not save")
		})
	}
}

func TestDeleteGroup(t *testing.T) {
	tt := []struct {
		name    string
		id      string
		code    int
		deleted string
		body    string
	}{
		{"deletes", "g1", http.StatusOK, "g1", "{}"},
		{"link error is a bad request with the first error", "linked", http.StatusBadRequest, "", "group has been linked to something"},
		{"unknown group is not found", "missing", http.StatusNotFound, "", ""},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			th := newTestHandler(t, testOptions{readAllPeers: true})
			rec := th.do(t, http.MethodDelete, "/groups/"+tc.id, "")
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			assert.Equal(t, tc.deleted, th.deleted)
			assert.Contains(t, rec.Body.String(), tc.body)
		})
	}
}

// A caller whose peer visibility cannot be resolved is denied before anything is written, so the
// client never gets an error for a change that was saved.
func TestVisibilityFailureDeniesBeforeMutation(t *testing.T) {
	tt := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"create", http.MethodPost, "/groups", `{"name":"devs"}`},
		{"update", http.MethodPut, "/groups/g1", `{"name":"devs","peers":["peer-a"]}`},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			th := newTestHandler(t, testOptions{permissionErr: errors.New("boom")}, apiGroup("g1", "devs", "peer-a"))
			rec := th.do(t, tc.method, tc.path, tc.body)
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Nil(t, th.saved, "group must not be saved")
		})
	}
}
