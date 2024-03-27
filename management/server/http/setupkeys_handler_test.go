package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/status"
)

const (
	existingSetupKeyID  = "existingSetupKeyID"
	newSetupKeyName     = "New Setup Key"
	updatedSetupKeyName = "KKKey"
	notFoundSetupKeyID  = "notFoundSetupKeyID"
)

func initSetupKeysTestMetaData(defaultKey *server.SetupKey, newKey *server.SetupKey, updatedSetupKey *server.SetupKey,
	user *server.User,
) *SetupKeysHandler {
	return &SetupKeysHandler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return &server.Account{
					Id:     testAccountID,
					Domain: "hotmail.com",
					Users: map[string]*server.User{
						user.Id: user,
					},
					SetupKeys: map[string]*server.SetupKey{
						defaultKey.Key: defaultKey,
					},
					Groups: map[string]*nbgroup.Group{
						"group-1": {ID: "group-1", Peers: []string{"A", "B"}},
						"id-all":  {ID: "id-all", Name: "All"},
					},
				}, user, nil
			},
			CreateSetupKeyFunc: func(_ string, keyName string, typ server.SetupKeyType, _ time.Duration, _ []string,
				_ int, _ string, ephemeral bool,
			) (*server.SetupKey, error) {
				if keyName == newKey.Name || typ != newKey.Type {
					nk := newKey.Copy()
					nk.Ephemeral = ephemeral
					return nk, nil
				}
				return nil, fmt.Errorf("failed creating setup key")
			},
			GetSetupKeyFunc: func(accountID, userID, keyID string) (*server.SetupKey, error) {
				switch keyID {
				case defaultKey.Id:
					return defaultKey, nil
				case newKey.Id:
					return newKey, nil
				default:
					return nil, status.Errorf(status.NotFound, "key %s not found", keyID)
				}
			},

			SaveSetupKeyFunc: func(accountID string, key *server.SetupKey, _ string) (*server.SetupKey, error) {
				if key.Id == updatedSetupKey.Id {
					return updatedSetupKey, nil
				}
				return nil, status.Errorf(status.NotFound, "key %s not found", key.Id)
			},

			ListSetupKeysFunc: func(accountID, userID string) ([]*server.SetupKey, error) {
				return []*server.SetupKey{defaultKey}, nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    user.Id,
					Domain:    "hotmail.com",
					AccountId: testAccountID,
				}
			}),
		),
	}
}

func TestSetupKeysHandlers(t *testing.T) {
	defaultSetupKey := server.GenerateDefaultSetupKey()
	defaultSetupKey.Id = existingSetupKeyID

	adminUser := server.NewAdminUser("test_user")

	newSetupKey := server.GenerateSetupKey(newSetupKeyName, server.SetupKeyReusable, 0, []string{"group-1"},
		server.SetupKeyUnlimitedUsage, true)
	updatedDefaultSetupKey := defaultSetupKey.Copy()
	updatedDefaultSetupKey.AutoGroups = []string{"group-1"}
	updatedDefaultSetupKey.Name = updatedSetupKeyName
	updatedDefaultSetupKey.Revoked = true

	tt := []struct {
		name              string
		requestType       string
		requestPath       string
		requestBody       io.Reader
		expectedStatus    int
		expectedBody      bool
		expectedSetupKey  *api.SetupKey
		expectedSetupKeys []*api.SetupKey
	}{
		{
			name:              "Get Setup Keys",
			requestType:       http.MethodGet,
			requestPath:       "/api/setup-keys",
			expectedStatus:    http.StatusOK,
			expectedBody:      true,
			expectedSetupKeys: []*api.SetupKey{toResponseBody(defaultSetupKey)},
		},
		{
			name:             "Get Existing Setup Key",
			requestType:      http.MethodGet,
			requestPath:      "/api/setup-keys/" + existingSetupKeyID,
			expectedStatus:   http.StatusOK,
			expectedBody:     true,
			expectedSetupKey: toResponseBody(defaultSetupKey),
		},
		{
			name:           "Get Not Existing Setup Key",
			requestType:    http.MethodGet,
			requestPath:    "/api/setup-keys/" + notFoundSetupKeyID,
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:        "Create Setup Key",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"name\":\"%s\",\"type\":\"%s\",\"expires_in\":86400, \"ephemeral\":true}", newSetupKey.Name, newSetupKey.Type))),
			expectedStatus:   http.StatusOK,
			expectedBody:     true,
			expectedSetupKey: toResponseBody(newSetupKey),
		},
		{
			name:        "Update Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/" + defaultSetupKey.Id,
			requestBody: bytes.NewBuffer(
				[]byte(fmt.Sprintf("{\"name\":\"%s\",\"auto_groups\":[\"%s\"], \"revoked\":%v}",
					updatedDefaultSetupKey.Type,
					updatedDefaultSetupKey.AutoGroups[0],
					updatedDefaultSetupKey.Revoked,
				))),
			expectedStatus:   http.StatusOK,
			expectedBody:     true,
			expectedSetupKey: toResponseBody(updatedDefaultSetupKey),
		},
	}

	handler := initSetupKeysTestMetaData(defaultSetupKey, newSetupKey, updatedDefaultSetupKey, adminUser)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/setup-keys", handler.GetAllSetupKeys).Methods("GET", "OPTIONS")
			router.HandleFunc("/api/setup-keys", handler.CreateSetupKey).Methods("POST", "OPTIONS")
			router.HandleFunc("/api/setup-keys/{keyId}", handler.GetSetupKey).Methods("GET", "OPTIONS")
			router.HandleFunc("/api/setup-keys/{keyId}", handler.UpdateSetupKey).Methods("PUT", "OPTIONS")
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

			if tc.expectedSetupKey != nil {
				got := &api.SetupKey{}
				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
				assertKeys(t, got, tc.expectedSetupKey)
				return
			}

			if len(tc.expectedSetupKeys) > 0 {
				var got []*api.SetupKey
				if err = json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
				assertKeys(t, got[0], tc.expectedSetupKeys[0])
				return
			}
		})
	}
}

func assertKeys(t *testing.T, got *api.SetupKey, expected *api.SetupKey) {
	t.Helper()
	// this comparison is done manually because when converting to JSON dates formatted differently
	// assert.Equal(t, got.UpdatedAt, tc.expectedSetupKey.UpdatedAt) //doesn't work
	assert.WithinDurationf(t, got.UpdatedAt, expected.UpdatedAt, 0, "")
	assert.WithinDurationf(t, got.Expires, expected.Expires, 0, "")
	assert.Equal(t, got.Name, expected.Name)
	assert.Equal(t, got.Id, expected.Id)
	assert.Equal(t, got.Key, expected.Key)
	assert.Equal(t, got.Type, expected.Type)
	assert.Equal(t, got.UsedTimes, expected.UsedTimes)
	assert.Equal(t, got.Revoked, expected.Revoked)
	assert.ElementsMatch(t, got.AutoGroups, expected.AutoGroups)
	assert.Equal(t, got.Ephemeral, expected.Ephemeral)
}
