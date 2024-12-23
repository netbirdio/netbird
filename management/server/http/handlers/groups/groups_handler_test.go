package groups

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/magiconair/properties/assert"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

var TestPeers = map[string]*nbpeer.Peer{
	"A": {Key: "A", ID: "peer-A-ID", IP: net.ParseIP("100.100.100.100")},
	"B": {Key: "B", ID: "peer-B-ID", IP: net.ParseIP("200.200.200.200")},
}

func initGroupTestData(initGroups ...*types.Group) *handler {
	return &handler{
		accountManager: &mock_server.MockAccountManager{
			SaveGroupFunc: func(_ context.Context, accountID, userID string, group *types.Group) error {
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
			GetAccountIDFromTokenFunc: func(_ context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error) {
				return claims.AccountId, claims.UserId, nil
			},
			GetGroupByNameFunc: func(ctx context.Context, groupName, _ string) (*types.Group, error) {
				if groupName == "All" {
					return &types.Group{ID: "id-all", Name: "All", Issued: types.GroupIssuedAPI}, nil
				}

				return nil, fmt.Errorf("unknown group name")
			},
			GetPeersFunc: func(ctx context.Context, accountID, userID string) ([]*nbpeer.Peer, error) {
				return maps.Values(TestPeers), nil
			},
			DeleteGroupFunc: func(_ context.Context, accountID, userId, groupID string) error {
				if groupID == "linked-grp" {
					return &server.GroupLinkError{
						Resource: "something",
						Name:     "linked-grp",
					}
				}
				if groupID == "invalid-grp" {
					return fmt.Errorf("internal error")
				}
				return nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
			}),
		),
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

	p := initGroupTestData(group)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

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

	p := initGroupTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

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

	p := initGroupTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)

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
