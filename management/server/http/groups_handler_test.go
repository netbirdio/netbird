package http

import (
	"bytes"
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

	"github.com/netbirdio/netbird/management/server"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
)

var TestPeers = map[string]*nbpeer.Peer{
	"A": {Key: "A", ID: "peer-A-ID", IP: net.ParseIP("100.100.100.100")},
	"B": {Key: "B", ID: "peer-B-ID", IP: net.ParseIP("200.200.200.200")},
}

func initGroupTestData(user *server.User, _ ...*nbgroup.Group) *GroupsHandler {
	return &GroupsHandler{
		accountManager: &mock_server.MockAccountManager{
			SaveGroupFunc: func(accountID, userID string, group *nbgroup.Group) error {
				if !strings.HasPrefix(group.ID, "id-") {
					group.ID = "id-was-set"
				}
				return nil
			},
			GetGroupFunc: func(_, groupID, _ string) (*nbgroup.Group, error) {
				if groupID != "idofthegroup" {
					return nil, status.Errorf(status.NotFound, "not found")
				}
				if groupID == "id-jwt-group" {
					return &nbgroup.Group{
						ID:     "id-jwt-group",
						Name:   "Default Group",
						Issued: nbgroup.GroupIssuedJWT,
					}, nil
				}
				return &nbgroup.Group{
					ID:     "idofthegroup",
					Name:   "Group",
					Issued: nbgroup.GroupIssuedAPI,
				}, nil
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Peers:  TestPeers,
					Users: map[string]*server.User{
						user.Id: user,
					},
					Groups: map[string]*nbgroup.Group{
						"id-jwt-group": {ID: "id-jwt-group", Name: "From JWT", Issued: nbgroup.GroupIssuedJWT},
						"id-existed":   {ID: "id-existed", Peers: []string{"A", "B"}, Issued: nbgroup.GroupIssuedAPI},
						"id-all":       {ID: "id-all", Name: "All", Issued: nbgroup.GroupIssuedAPI},
					},
				}, user, nil
			},
			DeleteGroupFunc: func(accountID, userId, groupID string) error {
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
			name:           "GetGroup OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/groups/idofthegroup",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GetGroup not found",
			requestType:    http.MethodGet,
			requestPath:    "/api/groups/notexists",
			expectedStatus: http.StatusNotFound,
		},
	}

	group := &nbgroup.Group{
		ID:   "idofthegroup",
		Name: "Group",
	}

	adminUser := server.NewAdminUser("test_user")
	p := initGroupTestData(adminUser, group)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/groups/{groupId}", p.GetGroup).Methods("GET")
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

			got := &nbgroup.Group{}
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

	adminUser := server.NewAdminUser("test_user")
	p := initGroupTestData(adminUser)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/groups", p.CreateGroup).Methods("POST")
			router.HandleFunc("/api/groups/{groupId}", p.UpdateGroup).Methods("PUT")
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

	adminUser := server.NewAdminUser("test_user")
	p := initGroupTestData(adminUser)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)

			router := mux.NewRouter()
			router.HandleFunc("/api/groups/{groupId}", p.DeleteGroup).Methods("DELETE")
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
