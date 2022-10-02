package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/http/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gorilla/mux"
	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

const (
	existingNSGroupID    = "existingNSGroupID"
	notFoundNSGroupID    = "notFoundNSGroupID"
	testNSGroupAccountID = "test_id"
)

var testingNSAccount = &server.Account{
	Id:     testNSGroupAccountID,
	Domain: "hotmail.com",
}

var baseExistingNSGroup = &nbdns.NameServerGroup{
	ID:          existingNSGroupID,
	Name:        "super",
	Description: "super",
	NameServers: []nbdns.NameServer{
		{
			IP:     netip.MustParseAddr("1.1.1.1"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
		{
			IP:     netip.MustParseAddr("1.1.2.2"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
	},
	Groups:  []string{"testing"},
	Enabled: true,
}

func initNameserversTestData() *Nameservers {
	return &Nameservers{
		accountManager: &mock_server.MockAccountManager{
			GetNameServerGroupFunc: func(accountID, nsGroupID string) (*nbdns.NameServerGroup, error) {
				if nsGroupID == existingNSGroupID {
					return baseExistingNSGroup.Copy(), nil
				}
				return nil, status.Errorf(codes.NotFound, "nameserver group with ID %s not found", nsGroupID)
			},
			CreateNameServerGroupFunc: func(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, enabled bool) (*nbdns.NameServerGroup, error) {
				return &nbdns.NameServerGroup{
					ID:          existingNSGroupID,
					Name:        name,
					Description: description,
					NameServers: nameServerList,
					Groups:      groups,
					Enabled:     enabled,
				}, nil
			},
			DeleteNameServerGroupFunc: func(accountID, nsGroupID string) error {
				return nil
			},
			SaveNameServerGroupFunc: func(accountID string, nsGroupToSave *nbdns.NameServerGroup) error {
				if nsGroupToSave.ID == existingNSGroupID {
					return nil
				}
				return status.Errorf(codes.NotFound, "nameserver group with ID %s was not found", nsGroupToSave.ID)
			},
			UpdateNameServerGroupFunc: func(accountID, nsGroupID string, operations []server.NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error) {
				nsGroupToUpdate := baseExistingNSGroup.Copy()
				if nsGroupID != nsGroupToUpdate.ID {
					return nil, status.Errorf(codes.NotFound, "nameserver group ID %s no longer exists", nsGroupID)
				}
				for _, operation := range operations {
					switch operation.Type {
					case server.UpdateNameServerGroupName:
						nsGroupToUpdate.Name = operation.Values[0]
					case server.UpdateNameServerGroupDescription:
						nsGroupToUpdate.Description = operation.Values[0]
					case server.UpdateNameServerGroupNameServers:
						var parsedNSList []nbdns.NameServer
						for _, nsURL := range operation.Values {
							parsed, err := nbdns.ParseNameServerURL(nsURL)
							if err != nil {
								return nil, err
							}
							parsedNSList = append(parsedNSList, parsed)
						}
						nsGroupToUpdate.NameServers = parsedNSList
					}
				}
				return nsGroupToUpdate, nil
			},
			GetAccountWithAuthorizationClaimsFunc: func(_ jwtclaims.AuthorizationClaims) (*server.Account, error) {
				return testingNSAccount, nil
			},
		},
		authAudience: "",
		jwtExtractor: jwtclaims.ClaimsExtractor{
			ExtractClaimsFromRequestContext: func(r *http.Request, authAudiance string) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: testNSGroupAccountID,
				}
			},
		},
	}
}

func TestNameserversHandlers(t *testing.T) {
	tt := []struct {
		name            string
		expectedStatus  int
		expectedBody    bool
		expectedNSGroup *api.NameserverGroup
		requestType     string
		requestPath     string
		requestBody     io.Reader
	}{
		{
			name:            "Get Existing Nameserver Group",
			requestType:     http.MethodGet,
			requestPath:     "/api/nameservers/" + existingNSGroupID,
			expectedStatus:  http.StatusOK,
			expectedBody:    true,
			expectedNSGroup: toNameserverGroupResponse(baseExistingNSGroup),
		},
		{
			name:           "Get Not Existing Nameserver Group",
			requestType:    http.MethodGet,
			requestPath:    "/api/nameservers/" + notFoundNSGroupID,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/nameservers",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1.1.1.1\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true}"))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedNSGroup: &api.NameserverGroup{
				Id:          existingNSGroupID,
				Name:        "name",
				Description: "Post",
				Nameservers: []api.Nameserver{
					{
						Ip:     "1.1.1.1",
						NsType: "udp",
						Port:   53,
					},
				},
				Groups:  []string{"group"},
				Enabled: true,
			},
		},
		{
			name:        "POST Invalid Nameserver",
			requestType: http.MethodPost,
			requestPath: "/api/nameservers",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1000\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true}"))),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
		{
			name:        "PUT OK",
			requestType: http.MethodPut,
			requestPath: "/api/nameservers/" + existingNSGroupID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1.1.1.1\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true}"))),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedNSGroup: &api.NameserverGroup{
				Id:          existingNSGroupID,
				Name:        "name",
				Description: "Post",
				Nameservers: []api.Nameserver{
					{
						Ip:     "1.1.1.1",
						NsType: "udp",
						Port:   53,
					},
				},
				Groups:  []string{"group"},
				Enabled: true,
			},
		},
		{
			name:        "PUT Not Existing Nameserver Group",
			requestType: http.MethodPut,
			requestPath: "/api/nameservers/" + notFoundNSGroupID,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"Name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"100\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true}"))),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:           "PUT Invalid Nameserver",
			requestType:    http.MethodPut,
			requestPath:    "/api/nameservers/" + notFoundNSGroupID,
			requestBody:    bytes.NewBufferString(fmt.Sprintf("{\"Description\":\"Post\",\"Network\":\"192.168.0.0/16\",\"network_id\":\"awesomeNet\",\"Peer\":\"%s\"}", existingPeerID)),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:           "PATCH OK",
			requestType:    http.MethodPatch,
			requestPath:    "/api/nameservers/" + existingNSGroupID,
			requestBody:    bytes.NewBufferString("[{\"op\":\"replace\",\"path\":\"description\",\"value\":[\"NewDesc\"]}]"),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedNSGroup: &api.NameserverGroup{
				Id:          existingNSGroupID,
				Name:        baseExistingNSGroup.Name,
				Description: "NewDesc",
				Nameservers: toNameserverGroupResponse(baseExistingNSGroup).Nameservers,
				Groups:      baseExistingNSGroup.Groups,
				Enabled:     baseExistingNSGroup.Enabled,
			},
		},
		{
			name:           "PATCH Invalid Nameserver Group OK",
			requestType:    http.MethodPatch,
			requestPath:    "/api/nameservers/" + notFoundRouteID,
			requestBody:    bytes.NewBufferString("[{\"op\":\"replace\",\"path\":\"description\",\"value\":[\"NewDesc\"]}]"),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
	}

	p := initNameserversTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/nameservers/{id}", p.GetNameserverGroupHandler).Methods("GET")
			router.HandleFunc("/api/nameservers", p.CreateNameserverGroupHandler).Methods("POST")
			router.HandleFunc("/api/nameservers/{id}", p.DeleteNameserverGroupHandler).Methods("DELETE")
			router.HandleFunc("/api/nameservers/{id}", p.UpdateNameserverGroupHandler).Methods("PUT")
			router.HandleFunc("/api/nameservers/{id}", p.PatchNameserverGroupHandler).Methods("PATCH")
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

			got := &api.Route{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}
			assert.Equal(t, got, tc.expectedNSGroup)
		})
	}
}
