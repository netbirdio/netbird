package peers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	peersmodule "github.com/netbirdio/netbird/management/internals/modules/peers"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetPeersPagination(t *testing.T) {
	peer := &nbpeer.Peer{
		ID:     testPeerID,
		Status: &nbpeer.PeerStatus{Connected: true},
		Meta:   nbpeer.PeerSystemMeta{},
	}

	tt := []struct {
		name            string
		expectedStatus  int
		requestPath     string
		setExpectations func(p *Handler)
	}{
		{
			name:           "GetPeers default paging, filtering, and sorting",
			requestPath:    "/peers",
			expectedStatus: http.StatusOK,
			setExpectations: func(p *Handler) {
				p.peersManager.(*peersmodule.MockManager).EXPECT().GetPeersPaginated(gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Eq(store.PaginationState{Page: 1, PageSize: 100}), gomock.Any(), gomock.Any()).Return(make([]*nbpeer.Peer, 0), 0, nil).AnyTimes()
			},
		},
		{
			name:           "GetPeers paging",
			requestPath:    "/peers?page=10&page_size=250",
			expectedStatus: http.StatusOK,
			setExpectations: func(p *Handler) {
				p.peersManager.(*peersmodule.MockManager).EXPECT().GetPeersPaginated(gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Eq(store.PaginationState{Page: 10, PageSize: 250}),
					gomock.Any(), gomock.Any()).Return(make([]*nbpeer.Peer, 0), 0, nil).AnyTimes()
			},
		},
		{
			name:            "GetPeers paging with invalid page",
			requestPath:     "/peers?page=aaa&page_size=250",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers paging with invalid page size",
			requestPath:     "/peers?page=10&page_size=aaa",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:           "GetPeers filtering all valid params",
			requestPath:    "/peers?user_id=test-user&group_ids=1&group_ids=2&group_ids=3&group_ids=4&peer_ids=peer-1&peer_ids=peer-2&connected=true&approval_required=false&os=linux&os=windows&os=mac&os=android&os=ios&os=js&ip=10.10.10.10&mac=00:11:22:33:44:55&hostname=test-host&kind=user_device",
			expectedStatus: http.StatusOK,
			setExpectations: func(p *Handler) {
				p.peersManager.(*peersmodule.MockManager).EXPECT().GetPeersPaginated(gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Eq(store.PaginationState{Page: 1, PageSize: 100}),
					gomock.Eq(store.PeerFilters{
						UserId:           "test-user",
						GroupIds:         []string{"1", "2", "3", "4"},
						Connected:        new(true),
						ApprovalRequired: new(false),
						Os:               []string{"linux", "windows", "mac", "android", "ios", "js"},
						IP:               "10.10.10.10",
						MAC:              "00:11:22:33:44:55",
						Hostname:         "test-host",
						IsServer:         new(false),
						PeersIds:         []string{"peer-1", "peer-2"},
					}),
					gomock.Any()).Return(make([]*nbpeer.Peer, 0), 0, nil).AnyTimes()
			},
		},
		{
			name:           "GetPeers filtering with kind server",
			requestPath:    "/peers?kind=server",
			expectedStatus: http.StatusOK,
			setExpectations: func(p *Handler) {
				p.peersManager.(*peersmodule.MockManager).EXPECT().GetPeersPaginated(gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Eq(store.PaginationState{Page: 1, PageSize: 100}),
					gomock.Eq(store.PeerFilters{IsServer: new(true)}),
					gomock.Any()).Return(make([]*nbpeer.Peer, 0), 0, nil).AnyTimes()
			},
		},
		{
			name:            "GetPeers filtering with invalid connected value",
			requestPath:     "/peers?connected=aaa",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers filtering with invalid approval_required value",
			requestPath:     "/peers?approval_required=aaa",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers filtering with invalid os value",
			requestPath:     "/peers?os=nosuchos",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers filtering with invalid kind value",
			requestPath:     "/peers?kind=nosuchkind",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers filtering with conflicting user_id and kind",
			requestPath:     "/peers?user_id=test-user&kind=server",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:           "GetPeers sorting preserves field ordering",
			requestPath:    "/peers?sort_by=last_seen&sort_by=name&sort_by=version",
			expectedStatus: http.StatusOK,
			setExpectations: func(p *Handler) {
				p.peersManager.(*peersmodule.MockManager).EXPECT().GetPeersPaginated(gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Eq(store.PaginationState{Page: 1, PageSize: 100}),
					gomock.Any(),
					gomock.Eq(store.PeerSorting{
						Fields: []store.PeerSortingKey{
							{Field: store.PeerSortByLastSeen, Order: store.AscOrderBy},
							{Field: store.PeerSortByName, Order: store.AscOrderBy},
							{Field: store.PeerSortByVersion, Order: store.AscOrderBy},
						},
					})).Return(make([]*nbpeer.Peer, 0), 0, nil).AnyTimes()
			},
		},
		{
			name:            "GetPeers sorting with invalid field",
			requestPath:     "/peers?sort_by=nosuchfield,asc",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers sorting with invalid field",
			requestPath:     "/peers?sort_by=nosuchfield,asc",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
		},
		{
			name:            "GetPeers sorting with invalid sorting order",
			requestPath:     "/peers?sort_by=name,nosuchorder&sort_by=version",
			expectedStatus:  http.StatusUnprocessableEntity,
			setExpectations: func(p *Handler) {},
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

			tc.setExpectations(p)
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)
		})
	}
}
