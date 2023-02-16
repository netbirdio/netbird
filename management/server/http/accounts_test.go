package http

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func initAccountsTestData(account *server.Account, admin *server.User) *Accounts {
	return &Accounts{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return account, admin, nil
			},
			UpdateAccountSettingsFunc: func(accountID, userID string, newSettings *server.Settings) (*server.Account, error) {
				halfYearLimit := 180 * 24 * time.Hour
				if newSettings.PeerLoginExpiration > halfYearLimit {
					return nil, status.Errorf(status.InvalidArgument, "peer login expiration can't be larger than 180 days")
				}

				if newSettings.PeerLoginExpiration < time.Hour {
					return nil, status.Errorf(status.InvalidArgument, "peer login expiration can't be smaller than one hour")
				}

				accCopy := account.Copy()
				accCopy.UpdateSettings(newSettings)
				return accCopy, nil

			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_account",
				}
			}),
		),
	}
}

func TestAccounts_AccountsHandler(t *testing.T) {

	accountID := "test_account"
	adminUser := server.NewAdminUser("test_user")

	handler := initAccountsTestData(&server.Account{
		Id:      accountID,
		Domain:  "hotmail.com",
		Network: server.NewNetwork(),
		Users: map[string]*server.User{
			adminUser.Id: adminUser,
		},
		Settings: &server.Settings{
			PeerLoginExpirationEnabled: false,
			PeerLoginExpiration:        time.Hour,
		},
	}, adminUser)

	tt := []struct {
		name             string
		expectedStatus   int
		expectedBody     bool
		expectedID       string
		expectedArray    bool
		expectedSettings api.AccountSettings
		requestType      string
		requestPath      string
		requestBody      io.Reader
	}{
		{
			name:           "GetAccounts OK",
			expectedBody:   true,
			requestType:    http.MethodGet,
			requestPath:    "/api/accounts",
			expectedStatus: http.StatusOK,
			expectedSettings: api.AccountSettings{
				PeerLoginExpiration:        float32(time.Hour.Seconds()),
				PeerLoginExpirationEnabled: false,
			},
			expectedArray: true,
			expectedID:    accountID,
		},
		{
			name:           "PutAccount OK",
			expectedBody:   true,
			requestType:    http.MethodPut,
			requestPath:    "/api/accounts/" + accountID,
			requestBody:    bytes.NewBufferString("{\"settings\": {\"peer_login_expiration\": 15552000,\"peer_login_expiration_enabled\": true}}"),
			expectedStatus: http.StatusOK,
			expectedSettings: api.AccountSettings{
				PeerLoginExpiration:        15552000,
				PeerLoginExpirationEnabled: true,
			},
			expectedArray: false,
			expectedID:    accountID,
		},
		{
			name:           "Update account failure with high peer_login_expiration more than 180 days",
			expectedBody:   true,
			requestType:    http.MethodPut,
			requestPath:    "/api/accounts/" + accountID,
			requestBody:    bytes.NewBufferString("{\"settings\": {\"peer_login_expiration\": 15552001,\"peer_login_expiration_enabled\": true}}"),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedArray:  false,
		},
		{
			name:           "Update account failure with peer_login_expiration less than an hour",
			expectedBody:   true,
			requestType:    http.MethodPut,
			requestPath:    "/api/accounts/" + accountID,
			requestBody:    bytes.NewBufferString("{\"settings\": {\"peer_login_expiration\": 3599,\"peer_login_expiration_enabled\": true}}"),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedArray:  false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/accounts", handler.GetAccountsHandler).Methods("GET")
			router.HandleFunc("/api/accounts/{id}", handler.UpdateAccountHandler).Methods("PUT")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
				return
			}

			if tc.expectedStatus != http.StatusOK {
				return
			}

			if !tc.expectedBody {
				return
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			var actual *api.Account
			if tc.expectedArray {
				var got []*api.Account
				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}

				assert.Len(t, got, 1)
				actual = got[0]
			} else {
				if err = json.Unmarshal(content, &actual); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
			}

			assert.Equal(t, tc.expectedID, actual.Id)
			assert.Equal(t, tc.expectedSettings, actual.Settings)
		})
	}
}
