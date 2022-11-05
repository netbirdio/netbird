package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/management/server/http/api"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

var TestPeers = map[string]*server.Peer{
	"A": &server.Peer{Key: "A", IP: net.ParseIP("100.100.100.100")},
	"B": &server.Peer{Key: "B", IP: net.ParseIP("200.200.200.200")},
}

func initGroupTestData(user *server.User, groups ...*server.Group) *Groups {
	return &Groups{
		accountManager: &mock_server.MockAccountManager{
			SaveGroupFunc: func(accountID string, group *server.Group) error {
				if !strings.HasPrefix(group.ID, "id-") {
					group.ID = "id-was-set"
				}
				return nil
			},
			GetGroupFunc: func(_, groupID string) (*server.Group, error) {
				if groupID != "idofthegroup" {
					return nil, fmt.Errorf("not found")
				}
				return &server.Group{
					ID:   "idofthegroup",
					Name: "Group",
				}, nil
			},
			UpdateGroupFunc: func(_ string, groupID string, operations []server.GroupUpdateOperation) (*server.Group, error) {
				var group server.Group
				group.ID = groupID
				for _, operation := range operations {
					switch operation.Type {
					case server.UpdateGroupName:
						group.Name = operation.Values[0]
					case server.UpdateGroupPeers, server.InsertPeersToGroup:
						group.Peers = operation.Values
					case server.RemovePeersFromGroup:
					default:
						return nil, fmt.Errorf("no operation")
					}
				}
				return &group, nil
			},
			GetPeerByIPFunc: func(_ string, peerIP string) (*server.Peer, error) {
				for _, peer := range TestPeers {
					if peer.IP.String() == peerIP {
						return peer, nil
					}
				}
				return nil, fmt.Errorf("peer not found")
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, error) {
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Peers:  TestPeers,
					Users: map[string]*server.User{
						user.Id: user,
					},
					Groups: map[string]*server.Group{
						"id-existed": {ID: "id-existed", Peers: []string{"A", "B"}},
						"id-all":     {ID: "id-all", Name: "All"}},
				}, nil
			},
		},
		authAudience: "",
		jwtExtractor: jwtclaims.ClaimsExtractor{
			ExtractClaimsFromRequestContext: func(r *http.Request, authAudiance string) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
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

	group := &server.Group{
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
			router.HandleFunc("/api/groups/{id}", p.GetGroupHandler).Methods("GET")
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

			got := &server.Group{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, got.ID, group.ID)
			assert.Equal(t, got.Name, group.Name)
		})
	}
}

func TestWriteGroup(t *testing.T) {
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
				Id:   "id-was-set",
				Name: "Default POSTed Group",
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
				Id:   "id-existed",
				Name: "Default POSTed Group",
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
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   false,
		},
		{
			name:        "Write Group PATCH Name OK",
			requestType: http.MethodPatch,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"replace","path":"name","value":["Default POSTed Group"]}]`)),
			expectedStatus: http.StatusOK,
			expectedGroup: &api.Group{
				Id:   "id-existed",
				Name: "Default POSTed Group",
			},
		},
		{
			name:        "Write Group PATCH Invalid Name OP",
			requestType: http.MethodPatch,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"insert","path":"name","value":[""]}]`)),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "Write Group PATCH Invalid Name",
			requestType: http.MethodPatch,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"replace","path":"name","value":[]}]`)),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "Write Group PATCH Peers OK",
			requestType: http.MethodPatch,
			requestPath: "/api/groups/id-existed",
			requestBody: bytes.NewBuffer(
				[]byte(`[{"op":"replace","path":"peers","value":["100.100.100.100","200.200.200.200"]}]`)),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedGroup: &api.Group{
				Id:         "id-existed",
				PeersCount: 2,
				Peers: []api.PeerMinimum{
					{Id: "100.100.100.100"},
					{Id: "200.200.200.200"}},
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
			router.HandleFunc("/api/groups", p.CreateGroupHandler).Methods("POST")
			router.HandleFunc("/api/groups/{id}", p.UpdateGroupHandler).Methods("PUT")
			router.HandleFunc("/api/groups/{id}", p.PatchGroupHandler).Methods("PATCH")
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
