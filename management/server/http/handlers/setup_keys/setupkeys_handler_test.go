package setup_keys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	existingSetupKeyID  = "existingSetupKeyID"
	newSetupKeyName     = "New Setup Key"
	updatedSetupKeyName = "KKKey"
	notFoundSetupKeyID  = "notFoundSetupKeyID"
)

func initSetupKeysTestMetaData(defaultKey *types.SetupKey, newKey *types.SetupKey, updatedSetupKey *types.SetupKey,
	user *types.User,
) *handler {
	return &handler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountIDFromTokenFunc: func(_ context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error) {
				return claims.AccountId, claims.UserId, nil
			},
			CreateSetupKeyFunc: func(_ context.Context, _ string, keyName string, typ types.SetupKeyType, _ time.Duration, _ []string,
				_ int, _ string, ephemeral bool,
			) (*types.SetupKey, error) {
				if keyName == newKey.Name || typ != newKey.Type {
					nk := newKey.Copy()
					nk.Ephemeral = ephemeral
					return nk, nil
				}
				return nil, fmt.Errorf("failed creating setup key")
			},
			GetSetupKeyFunc: func(_ context.Context, accountID, userID, keyID string) (*types.SetupKey, error) {
				switch keyID {
				case defaultKey.Id:
					return defaultKey, nil
				case newKey.Id:
					return newKey, nil
				default:
					return nil, status.Errorf(status.NotFound, "key %s not found", keyID)
				}
			},

			SaveSetupKeyFunc: func(_ context.Context, accountID string, key *types.SetupKey, _ string) (*types.SetupKey, error) {
				if key.Id == updatedSetupKey.Id {
					return updatedSetupKey, nil
				}
				return nil, status.Errorf(status.NotFound, "key %s not found", key.Id)
			},

			ListSetupKeysFunc: func(_ context.Context, accountID, userID string) ([]*types.SetupKey, error) {
				return []*types.SetupKey{defaultKey}, nil
			},

			DeleteSetupKeyFunc: func(_ context.Context, accountID, userID, keyID string) error {
				if keyID == defaultKey.Id {
					return nil
				}
				return status.Errorf(status.NotFound, "key %s not found", keyID)
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    user.Id,
					Domain:    "hotmail.com",
					AccountId: "testAccountId",
				}
			}),
		),
	}
}

func TestSetupKeysHandlers(t *testing.T) {
	defaultSetupKey, _ := types.GenerateDefaultSetupKey()
	defaultSetupKey.Id = existingSetupKeyID

	adminUser := types.NewAdminUser("test_user")

	newSetupKey, plainKey := types.GenerateSetupKey(newSetupKeyName, types.SetupKeyReusable, 0, []string{"group-1"},
		types.SetupKeyUnlimitedUsage, true)
	newSetupKey.Key = plainKey
	updatedDefaultSetupKey := defaultSetupKey.Copy()
	updatedDefaultSetupKey.AutoGroups = []string{"group-1"}
	updatedDefaultSetupKey.Name = updatedSetupKeyName
	updatedDefaultSetupKey.Revoked = true

	expectedNewKey := ToResponseBody(newSetupKey)
	expectedNewKey.Key = plainKey
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
			expectedSetupKeys: []*api.SetupKey{ToResponseBody(defaultSetupKey)},
		},
		{
			name:             "Get Existing Setup Key",
			requestType:      http.MethodGet,
			requestPath:      "/api/setup-keys/" + existingSetupKeyID,
			expectedStatus:   http.StatusOK,
			expectedBody:     true,
			expectedSetupKey: ToResponseBody(defaultSetupKey),
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
			expectedSetupKey: expectedNewKey,
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
			expectedSetupKey: ToResponseBody(updatedDefaultSetupKey),
		},
		{
			name:           "Delete Setup Key",
			requestType:    http.MethodDelete,
			requestPath:    "/api/setup-keys/" + defaultSetupKey.Id,
			requestBody:    bytes.NewBuffer([]byte("")),
			expectedStatus: http.StatusOK,
			expectedBody:   false,
		},
	}

	handler := initSetupKeysTestMetaData(defaultSetupKey, newSetupKey, updatedDefaultSetupKey, adminUser)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/setup-keys", handler.getAllSetupKeys).Methods("GET", "OPTIONS")
			router.HandleFunc("/api/setup-keys", handler.createSetupKey).Methods("POST", "OPTIONS")
			router.HandleFunc("/api/setup-keys/{keyId}", handler.getSetupKey).Methods("GET", "OPTIONS")
			router.HandleFunc("/api/setup-keys/{keyId}", handler.updateSetupKey).Methods("PUT", "OPTIONS")
			router.HandleFunc("/api/setup-keys/{keyId}", handler.deleteSetupKey).Methods("DELETE", "OPTIONS")
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
	// assert.Equal(t, got.UpdatedAt, tc.expectedResponse.UpdatedAt) //doesn't work
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
