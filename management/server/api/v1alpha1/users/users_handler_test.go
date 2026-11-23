package users

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
)

const (
	existingAccountID         = "existingAccountID"
	testDomain                = "hotmail.com"
	existingUserID            = "existingUserID"
	serviceUserID             = "serviceUserID"
	nonDeletableServiceUserID = "nonDeletableServiceUserID"
	regularUserID             = "regularUserID"
)

var usersTestAccount = &types.Account{
	Id:     existingAccountID,
	Domain: testDomain,
	Users: map[string]*types.User{
		existingUserID: {
			Id:            existingUserID,
			Role:          "admin",
			IsServiceUser: false,
			AutoGroups:    []string{"group_1"},
			Issued:        types.UserIssuedAPI,
		},
		regularUserID: {
			Id:            regularUserID,
			Role:          "user",
			IsServiceUser: false,
			AutoGroups:    []string{"group_1"},
			Issued:        types.UserIssuedAPI,
		},
		serviceUserID: {
			Id:            serviceUserID,
			Role:          "user",
			IsServiceUser: true,
			AutoGroups:    []string{"group_1"},
			Issued:        types.UserIssuedAPI,
		},
		nonDeletableServiceUserID: {
			Id:            nonDeletableServiceUserID,
			Role:          "admin",
			IsServiceUser: true,
			NonDeletable:  true,
			Issued:        types.UserIssuedIntegration,
		},
	},
}

func initUsersTestData() *Handler {
	return &Handler{
		accountManager: &mock_server.MockAccountManager{},
	}
}

func TestGetUsers(t *testing.T) {
	// Filtering and paging happen in the store. The handler must pass the query through,
	// keep the manager's order, and wrap the page in a UserBatch.
	listed := []string{serviceUserID, existingUserID, regularUserID}
	const totalUsers = 42

	tt := []struct {
		name               string
		requestPath        string
		expectedPagination store.PaginationState
		expectedFilters    store.UserFilters
		expectedSorting    store.UserSorting
	}{
		{name: "all users", requestPath: "/users?page=1&page_size=10", expectedPagination: store.PaginationState{Page: 1, PageSize: 10}},
		{name: "default page and page size", requestPath: "/users", expectedPagination: store.PaginationState{Page: 1, PageSize: 100}},
		{name: "service users", requestPath: "/users?page=2&page_size=5&service_user=true", expectedPagination: store.PaginationState{Page: 2, PageSize: 5}, expectedFilters: store.UserFilters{ServiceUser: new(true)}},
		{name: "regular users", requestPath: "/users?page=1&page_size=10&service_user=false", expectedPagination: store.PaginationState{Page: 1, PageSize: 10}, expectedFilters: store.UserFilters{ServiceUser: new(false)}},
		{
			name:               "role, pending approval, group and id filters",
			requestPath:        "/users?role=admin&role=network_admin&pending_approval=true&group_ids=grp-a&group_ids=grp-b&user_ids=" + regularUserID,
			expectedPagination: store.PaginationState{Page: 1, PageSize: 100},
			expectedFilters: store.UserFilters{
				Roles:           []types.UserRole{types.UserRoleAdmin, types.UserRoleNetworkAdmin},
				PendingApproval: new(true),
				GroupIDs:        []string{"grp-a", "grp-b"},
				UserIDs:         []string{regularUserID},
			},
		},
		{
			name:               "sorting keeps the field order",
			requestPath:        "/users?sort_by=is_current,desc&sort_by=role&sort_by=last_login,asc",
			expectedPagination: store.PaginationState{Page: 1, PageSize: 100},
			expectedSorting: store.UserSorting{Fields: []store.UserSortingKey{
				{Field: store.UserSortByIsCurrent, Order: store.DescOrderBy},
				{Field: store.UserSortByRole, Order: store.AscOrderBy},
				{Field: store.UserSortByLastLogin, Order: store.AscOrderBy},
			}},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var gotPagination store.PaginationState
			var gotFilters store.UserFilters
			var gotSorting store.UserSorting

			userHandler := initUsersTestData()
			userHandler.accountManager.(*mock_server.MockAccountManager).GetUsersFromAccountPaginatedFunc = func(_ context.Context, _, _ string, pagination store.PaginationState, filters store.UserFilters, sorting store.UserSorting) ([]*types.UserInfo, int, error) {
				gotPagination, gotFilters, gotSorting = pagination, filters, sorting
				infos := make([]*types.UserInfo, 0, len(listed))
				for _, id := range listed {
					u := usersTestAccount.Users[id]
					infos = append(infos, &types.UserInfo{ID: u.Id, Role: string(u.Role), IsServiceUser: u.IsServiceUser, Issued: u.Issued})
				}
				return infos, totalUsers, nil
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			require.NoError(t, err)
			router := mux.NewRouter()
			router.Use(v1validator.Handler)

			router = userHandler.WithEndpointsForRouter(router)
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, recorder.Code, "status code, content: %s", string(content))

			assert.Equal(t, tc.expectedPagination, gotPagination, "pagination passed to the manager")
			assert.Equal(t, tc.expectedFilters, gotFilters, "filters passed to the manager")
			assert.Equal(t, tc.expectedSorting, gotSorting, "sorting passed to the manager")

			var batch apiv1alpha1.UserBatch
			require.NoError(t, json.Unmarshal(content, &batch))

			assert.Equal(t, totalUsers, batch.UserCount, "user_count should be the manager's total")
			assert.Equal(t, tc.expectedPagination.Page, batch.Page, "page should echo the request")
			assert.Equal(t, tc.expectedPagination.PageSize, batch.PageSize, "page_size should echo the request")

			gotIDs := make([]string, 0, len(batch.Users))
			for _, u := range batch.Users {
				gotIDs = append(gotIDs, u.Id)
				assert.Equal(t, string(usersTestAccount.Users[u.Id].Role), u.Role, "role of %s", u.Id)
				isServiceUser := usersTestAccount.Users[u.Id].IsServiceUser
				assert.Equal(t, &isServiceUser, u.IsServiceUser, "is_service_user of %s", u.Id)
			}
			assert.Equal(t, listed, gotIDs, "users should keep the manager's order")
		})
	}
}

func TestGetUsersRejectsInvalidQuery(t *testing.T) {
	for _, requestPath := range []string{
		"/users?page_size=500",
		"/users?pending_approval=maybe",
		"/users?role=nosuchrole",
		// name is not sortable, as names are encrypted at rest
		"/users?sort_by=name",
		"/users?sort_by=role,sideways",
		"/users?sort_by=asc",
	} {
		t.Run(requestPath, func(t *testing.T) {
			userHandler := initUsersTestData()
			called := false
			userHandler.accountManager.(*mock_server.MockAccountManager).GetUsersFromAccountPaginatedFunc = func(context.Context, string, string, store.PaginationState, store.UserFilters, store.UserSorting) ([]*types.UserInfo, int, error) {
				called = true
				return nil, 0, nil
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, requestPath, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			require.NoError(t, err)
			router := mux.NewRouter()
			router.Use(v1validator.Handler)
			router = userHandler.WithEndpointsForRouter(router)
			router.ServeHTTP(recorder, req)

			assert.Equal(t, http.StatusUnprocessableEntity, recorder.Code, "status code for %s, body: %s", requestPath, recorder.Body.String())
			assert.False(t, called, "the manager must not be called for %s", requestPath)
		})
	}
}

func serveUsersRequest(t *testing.T, h *Handler, path string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    existingUserID,
		Domain:    testDomain,
		AccountId: existingAccountID,
	})

	v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
	require.NoError(t, err)
	router := mux.NewRouter()
	router.Use(v1validator.Handler)
	router = h.WithEndpointsForRouter(router)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestGetUser(t *testing.T) {
	tt := []struct {
		name           string
		found          []*types.UserInfo
		expectedStatus int
	}{
		{name: "visible user", found: []*types.UserInfo{{ID: regularUserID, Role: "user"}}, expectedStatus: http.StatusOK},
		// the list query returns nothing for users that don't exist or that the caller can't see
		{name: "missing or hidden user", expectedStatus: http.StatusNotFound},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var gotPagination store.PaginationState
			var gotFilters store.UserFilters
			h := initUsersTestData()
			h.accountManager.(*mock_server.MockAccountManager).GetUsersFromAccountPaginatedFunc = func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.UserFilters, _ store.UserSorting) ([]*types.UserInfo, int, error) {
				assert.Equal(t, existingAccountID, accountID, "account ID")
				assert.Equal(t, existingUserID, userID, "initiator ID")
				gotPagination, gotFilters = pagination, filters
				return tc.found, len(tc.found), nil
			}

			recorder := serveUsersRequest(t, h, "/users/"+regularUserID)
			require.Equal(t, tc.expectedStatus, recorder.Code, "status code, body: %s", recorder.Body.String())

			assert.Equal(t, store.PaginationState{Page: 1, PageSize: 1}, gotPagination, "pagination passed to the manager")
			assert.Equal(t, store.UserFilters{UserIDs: []string{regularUserID}}, gotFilters, "filters passed to the manager")

			if tc.expectedStatus == http.StatusOK {
				var user apiv1alpha1.User
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &user))
				assert.Equal(t, regularUserID, user.Id, "user ID")
			}
		})
	}
}
