package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

const (
	testDNSSettingsAccountID     = "test_id"
	testDNSSettingsExistingGroup = "test_group"
	testDNSSettingsUserID        = "test_user"
)

var baseExistingDNSSettings = server.DNSSettings{
	DisabledManagementGroups: []string{testDNSSettingsExistingGroup},
}

var testingDNSSettingsAccount = &server.Account{
	Id:     testDNSSettingsAccountID,
	Domain: "hotmail.com",
	Users: map[string]*server.User{
		testDNSSettingsUserID: server.NewAdminUser("test_user"),
	},
	DNSSettings: baseExistingDNSSettings,
}

func initDNSSettingsTestData() *DNSSettingsHandler {
	return &DNSSettingsHandler{
		accountManager: &mock_server.MockAccountManager{
			GetDNSSettingsFunc: func(accountID string, userID string) (*server.DNSSettings, error) {
				return &testingDNSSettingsAccount.DNSSettings, nil
			},
			SaveDNSSettingsFunc: func(accountID string, userID string, dnsSettingsToSave *server.DNSSettings) error {
				if dnsSettingsToSave != nil {
					return nil
				}
				return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
			},
			GetAccountFromTokenFunc: func(_ jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return testingDNSSettingsAccount, testingDNSSettingsAccount.Users[testDNSSettingsUserID], nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: testDNSSettingsAccountID,
				}
			}),
		),
	}
}

func TestDNSSettingsHandlers(t *testing.T) {
	tt := []struct {
		name                string
		expectedStatus      int
		expectedBody        bool
		expectedDNSSettings *api.DNSSettings
		requestType         string
		requestPath         string
		requestBody         io.Reader
	}{
		{
			name:           "Get DNS Settings",
			requestType:    http.MethodGet,
			requestPath:    "/api/dns/settings",
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedDNSSettings: &api.DNSSettings{
				DisabledManagementGroups: baseExistingDNSSettings.DisabledManagementGroups,
			},
		},
		{
			name:        "Update DNS Settings",
			requestType: http.MethodPut,
			requestPath: "/api/dns/settings",
			requestBody: bytes.NewBuffer(
				[]byte("{\"disabled_management_groups\":[\"group1\",\"group2\"]}")),
			expectedStatus: http.StatusOK,
			expectedBody:   true,
			expectedDNSSettings: &api.DNSSettings{
				DisabledManagementGroups: []string{"group1", "group2"},
			},
		},
		{
			name:        "Update DNS Settings Empty Body",
			requestType: http.MethodPut,
			requestPath: "/api/dns/settings",
			requestBody: bytes.NewBuffer(
				[]byte("{}")),
			expectedStatus:      http.StatusOK,
			expectedBody:        true,
			expectedDNSSettings: &api.DNSSettings{},
		},
	}

	p := initDNSSettingsTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/dns/settings", p.GetDNSSettings).Methods("GET")
			router.HandleFunc("/api/dns/settings", p.UpdateDNSSettings).Methods("PUT")
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

			got := &api.DNSSettings{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}
			assert.Equal(t, tc.expectedDNSSettings, got)
		})
	}
}
