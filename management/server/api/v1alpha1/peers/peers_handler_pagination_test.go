package peers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestGetPeersPagination(t *testing.T) {
	peer := &nbpeer.Peer{
		ID:     testPeerID,
		Status: &nbpeer.PeerStatus{Connected: true},
		Meta:   nbpeer.PeerSystemMeta{},
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestPath    string
		getPeersFunc   func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error)
	}{
		{
			name:           "GetPeers default paging, filtering, and sorting",
			requestPath:    "/peers",
			expectedStatus: http.StatusOK,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
					tt.Helper()
					assert.Equal(tt, store.PaginationState{Page: 1, PageSize: 100}, pagination)
					assert.Equal(tt, store.PeerFilters{}, filters)
					assert.Equal(tt, store.PeerSorting{}, sorting)
					return make([]*nbpeer.Peer, 0), 0, nil
				}
			},
		},
		{
			name:           "GetPeers paging",
			requestPath:    "/peers?page=10&page_size=250",
			expectedStatus: http.StatusOK,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
					tt.Helper()
					assert.Equal(tt, store.PaginationState{Page: 10, PageSize: 250}, pagination)
					return make([]*nbpeer.Peer, 0), 0, nil
				}
			},
		},
		{
			name:           "GetPeers paging with invalid page",
			requestPath:    "/peers?page=aaa&page_size=250",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers paging with invalid page size",
			requestPath:    "/peers?page=10&page_size=aaa",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers filtering all valid params",
			requestPath:    "/peers?user_id=test-user&group_ids=1&group_ids=2&group_ids=3&group_ids=4&connected=true&approval_required=false&os=linux&os=windows&os=mac&os=android&os=ios&os=js&ip=10.10.10.10&mac=00:11:22:33:44:55&hostname=test-host&kind=user_device",
			expectedStatus: http.StatusOK,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
					tt.Helper()
					assert.Equal(tt, store.PaginationState{Page: 1, PageSize: 100}, pagination)
					assert.Equal(tt, store.PeerFilters{
						UserId:           "test-user",
						GroupIds:         []string{"1", "2", "3", "4"},
						Connected:        new(true),
						ApprovalRequried: new(false),
						Os:               []string{"linux", "windows", "mac", "android", "ios", "js"},
						IP:               "10.10.10.10",
						MAC:              "00:11:22:33:44:55",
						Hostname:         "test-host",
						IsServer:         new(false),
					}, filters)
					assert.Equal(tt, store.PeerSorting{}, sorting)
					return make([]*nbpeer.Peer, 0), 0, nil
				}
			},
		},
		{
			name:           "GetPeers filtering with kind server",
			requestPath:    "/peers?kind=server",
			expectedStatus: http.StatusOK,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
					tt.Helper()
					assert.Equal(tt, store.PaginationState{Page: 1, PageSize: 100}, pagination)
					assert.Equal(tt, store.PeerFilters{
						IsServer: new(true),
					}, filters)
					assert.Equal(tt, store.PeerSorting{}, sorting)
					return make([]*nbpeer.Peer, 0), 0, nil
				}
			},
		},
		{
			name:           "GetPeers filtering with invalid connected value",
			requestPath:    "/peers?connected=aaa",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers filtering with invalid approval_required value",
			requestPath:    "/peers?approval_required=aaa",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers filtering with invalid os value",
			requestPath:    "/peers?os=nosuchos",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers filtering with invalid kind value",
			requestPath:    "/peers?kind=nosuchkind",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers filtering with conflicting user_id and kind",
			requestPath:    "/peers?user_id=test-user&kind=server",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers sorting with all valid parameters",
			requestPath:    "/peers?sort_by=name&sort_by=last_seen,desc&sort_by=ip,asc&sort_by=version,desc",
			expectedStatus: http.StatusOK,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
					tt.Helper()
					assert.Equal(tt, store.PaginationState{Page: 1, PageSize: 100}, pagination)
					assert.Equal(tt, store.PeerFilters{}, filters)
					assert.Equal(tt, store.PeerSorting{
						Fields: []store.PeerSortingKey{
							{Field: store.PeerSortByName, Order: store.AscOrderBy},
							{Field: store.PeerSortByLastSeen, Order: store.DescOrderBy},
							{Field: store.PeerSortByIP, Order: store.AscOrderBy},
							{Field: store.PeerSortByVersion, Order: store.DescOrderBy},
						},
					}, sorting)
					return make([]*nbpeer.Peer, 0), 0, nil
				}
			},
		},
		{
			name:           "GetPeers sorting with invalid field",
			requestPath:    "/peers?sort_by=nosuchfield,asc",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
		{
			name:           "GetPeers sorting with invalid sorting order",
			requestPath:    "/peers?sort_by=name,nosuchorder&sort_by=ip",
			expectedStatus: http.StatusUnprocessableEntity,
			getPeersFunc: func(tt *testing.T) func(_ context.Context, accountID, userID string, pagination store.PaginationState, filters store.PeerFilters, sorting store.PeerSorting) ([]*nbpeer.Peer, int, error) {
				return nil
			},
		},
	}

	p := initTestMetaData(t, peer)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "admin_user",
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			assert.NoError(t, err)
			router := mux.NewRouter()
			router.Use(v1validator.Handler)
			router = p.WithEndpointsForRouter(router)

			p.accountManager.(*mock_server.MockAccountManager).GetPeersFunc = tc.getPeersFunc(t)
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)
		})
	}
}
