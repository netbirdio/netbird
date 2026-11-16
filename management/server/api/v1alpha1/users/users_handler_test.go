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
	serviceOnly, regularOnly := true, false

	tt := []struct {
		name                string
		requestPath         string
		expectedPagination  store.PaginationState
		expectedServiceUser *bool
	}{
		{name: "all users", requestPath: "/users?page=1&page_size=10", expectedPagination: store.PaginationState{Page: 1, PageSize: 10}},
		{name: "service users", requestPath: "/users?page=2&page_size=5&service_user=true", expectedPagination: store.PaginationState{Page: 2, PageSize: 5}, expectedServiceUser: &serviceOnly},
		{name: "regular users", requestPath: "/users?page=1&page_size=10&service_user=false", expectedPagination: store.PaginationState{Page: 1, PageSize: 10}, expectedServiceUser: &regularOnly},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var gotPagination store.PaginationState
			var gotFilters store.UserFilters

			userHandler := initUsersTestData()
			userHandler.accountManager.(*mock_server.MockAccountManager).GetUsersFromAccountPaginatedFunc = func(_ context.Context, _, _ string, pagination store.PaginationState, filters store.UserFilters, _ store.UserSorting) ([]*types.UserInfo, int, error) {
				gotPagination, gotFilters = pagination, filters
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
			assert.Equal(t, tc.expectedServiceUser, gotFilters.ServiceUser, "service_user filter passed to the manager")

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
