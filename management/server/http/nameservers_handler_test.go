package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/gorilla/mux"

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
	Users: map[string]*server.User{
		"test_user": server.NewAdminUser("test_user"),
	},
}

var baseExistingNSGroup = &nbdns.NameServerGroup{
	ID:          existingNSGroupID,
	Name:        "super",
	Description: "super",
	Primary:     true,
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
	Domains: []string{"domain"},
	Enabled: true,
}

func initNameserversTestData() *NameserversHandler {
	return &NameserversHandler{
		accountManager: &mock_server.MockAccountManager{
			GetNameServerGroupFunc: func(accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error) {
				if nsGroupID == existingNSGroupID {
					return baseExistingNSGroup.Copy(), nil
				}
				return nil, status.Errorf(status.NotFound, "nameserver group with ID %s not found", nsGroupID)
			},
			CreateNameServerGroupFunc: func(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, _ string, searchDomains bool) (*nbdns.NameServerGroup, error) {
				return &nbdns.NameServerGroup{
					ID:                   existingNSGroupID,
					Name:                 name,
					Description:          description,
					NameServers:          nameServerList,
					Groups:               groups,
					Enabled:              enabled,
					Primary:              primary,
					Domains:              domains,
					SearchDomainsEnabled: searchDomains,
				}, nil
			},
			DeleteNameServerGroupFunc: func(accountID, nsGroupID, _ string) error {
				return nil
			},
			SaveNameServerGroupFunc: func(accountID, _ string, nsGroupToSave *nbdns.NameServerGroup) error {
				if nsGroupToSave.ID == existingNSGroupID {
					return nil
				}
				return status.Errorf(status.NotFound, "nameserver group with ID %s was not found", nsGroupToSave.ID)
			},
			GetAccountFromTokenFunc: func(_ jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return testingNSAccount, testingAccount.Users["test_user"], nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: testNSGroupAccountID,
				}
			}),
		),
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
			requestPath:     "/api/dns/nameservers/" + existingNSGroupID,
			expectedStatus:  http.StatusOK,
			expectedBody:    true,
			expectedNSGroup: toNameserverGroupResponse(baseExistingNSGroup),
		},
		{
			name:           "Get Not Existing Nameserver Group",
			requestType:    http.MethodGet,
			requestPath:    "/api/dns/nameservers/" + notFoundNSGroupID,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "POST OK",
			requestType: http.MethodPost,
			requestPath: "/api/dns/nameservers",
			requestBody: bytes.NewBuffer(
				[]byte("{\"name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1.1.1.1\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true,\"primary\":true}")),
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
				Primary: true,
			},
		},
		{
			name:        "POST Invalid Nameserver",
			requestType: http.MethodPost,
			requestPath: "/api/dns/nameservers",
			requestBody: bytes.NewBuffer(
				[]byte("{\"name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1000\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true,\"primary\":true}")),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
		{
			name:        "PUT OK",
			requestType: http.MethodPut,
			requestPath: "/api/dns/nameservers/" + existingNSGroupID,
			requestBody: bytes.NewBuffer(
				[]byte("{\"name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1.1.1.1\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true,\"primary\":true}")),
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
				Primary: true,
			},
		},
		{
			name:        "PUT Not Existing Nameserver Group",
			requestType: http.MethodPut,
			requestPath: "/api/dns/nameservers/" + notFoundNSGroupID,
			requestBody: bytes.NewBuffer(
				[]byte("{\"name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"1.1.1.1\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true,\"primary\":true}")),
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:        "PUT Invalid Nameserver",
			requestType: http.MethodPut,
			requestPath: "/api/dns/nameservers/" + notFoundNSGroupID,
			requestBody: bytes.NewBuffer(
				[]byte("{\"name\":\"name\",\"Description\":\"Post\",\"nameservers\":[{\"ip\":\"100\",\"ns_type\":\"udp\",\"port\":53}],\"groups\":[\"group\"],\"enabled\":true,\"primary\":true}")),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   false,
		},
	}

	p := initNameserversTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/dns/nameservers/{nsgroupId}", p.GetNameserverGroup).Methods("GET")
			router.HandleFunc("/api/dns/nameservers", p.CreateNameserverGroup).Methods("POST")
			router.HandleFunc("/api/dns/nameservers/{nsgroupId}", p.DeleteNameserverGroup).Methods("DELETE")
			router.HandleFunc("/api/dns/nameservers/{nsgroupId}", p.UpdateNameserverGroup).Methods("PUT")
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

			got := &api.NameserverGroup{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}
			assert.Equal(t, tc.expectedNSGroup, got)
		})
	}
}
