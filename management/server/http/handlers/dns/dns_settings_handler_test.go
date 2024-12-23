package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

const (
	testDNSSettingsAccountID     = "test_id"
	testDNSSettingsExistingGroup = "test_group"
	testDNSSettingsUserID        = "test_user"
)

var baseExistingDNSSettings = types.DNSSettings{
	DisabledManagementGroups: []string{testDNSSettingsExistingGroup},
}

var testingDNSSettingsAccount = &types.Account{
	Id:     testDNSSettingsAccountID,
	Domain: "hotmail.com",
	Users: map[string]*types.User{
		testDNSSettingsUserID: types.NewAdminUser("test_user"),
	},
	DNSSettings: baseExistingDNSSettings,
}

func initDNSSettingsTestData() *dnsSettingsHandler {
	return &dnsSettingsHandler{
		accountManager: &mock_server.MockAccountManager{
			GetDNSSettingsFunc: func(ctx context.Context, accountID string, userID string) (*types.DNSSettings, error) {
				return &testingDNSSettingsAccount.DNSSettings, nil
			},
			SaveDNSSettingsFunc: func(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error {
				if dnsSettingsToSave != nil {
					return nil
				}
				return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
			},
			GetAccountIDFromTokenFunc: func(ctx context.Context, _ jwtclaims.AuthorizationClaims) (string, string, error) {
				return testingDNSSettingsAccount.Id, testingDNSSettingsAccount.Users[testDNSSettingsUserID].Id, nil
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
			router.HandleFunc("/api/dns/settings", p.getDNSSettings).Methods("GET")
			router.HandleFunc("/api/dns/settings", p.updateDNSSettings).Methods("PUT")
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
