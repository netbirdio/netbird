//go:build component

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	testAccountId = "testUserId"
	testUserId    = "testAccountId"
	testPeerId    = "testPeerId"

	newKeyName = "newKey"
	expiresIn  = 3600

	existingKeyName = "existingKey"
)

func Test_SetupKeys(t *testing.T) {
	truePointer := true
	tt := []struct {
		name             string
		expectedStatus   int
		expectedResponse *api.SetupKey
		requestBody      *api.CreateSetupKeyRequest
		requestType      string
		requestPath      string
	}{
		{
			name:        "Create Setup Key",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: nil,
				ExpiresIn:  expiresIn,
				Name:       newKeyName,
				Type:       "reusable",
				UsageLimit: 0,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       newKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "reusable",
				UpdatedAt:  time.Now(),
				UsageLimit: 0,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:        "Create Setup Key with already existing name",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: nil,
				ExpiresIn:  expiresIn,
				Name:       existingKeyName,
				Type:       "one-off",
				UsageLimit: 0,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "one-off",
				UpdatedAt:  time.Now(),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:        "Create Setup Key as on-off with more than one usage",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: nil,
				ExpiresIn:  expiresIn,
				Name:       newKeyName,
				Type:       "one-off",
				UsageLimit: 3,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       newKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "one-off",
				UpdatedAt:  time.Now(),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:        "Create Setup Key with expiration in the past",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: nil,
				ExpiresIn:  -expiresIn,
				Name:       newKeyName,
				Type:       "one-off",
				UsageLimit: 0,
			},
			expectedStatus:   http.StatusUnprocessableEntity,
			expectedResponse: nil,
		},
		{
			name:        "Create Setup Key with AutoGroups that do exist",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: []string{"testGroup"},
				ExpiresIn:  expiresIn,
				Name:       newKeyName,
				Type:       "reusable",
				UsageLimit: 0,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{"testGroup"},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       newKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "reusable",
				UpdatedAt:  time.Now(),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:        "Create Setup Key for ephemeral peers",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: []string{},
				ExpiresIn:  expiresIn,
				Name:       newKeyName,
				Type:       "reusable",
				Ephemeral:  &truePointer,
				UsageLimit: 1,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{},
				Ephemeral:  true,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       newKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "reusable",
				UpdatedAt:  time.Now(),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:        "Create Setup Key with AutoGroups that do not exist",
			requestType: http.MethodPost,
			requestPath: "/api/setup-keys",
			requestBody: &api.CreateSetupKeyRequest{
				AutoGroups: []string{"someGroupID"},
				ExpiresIn:  expiresIn,
				Name:       newKeyName,
				Type:       "reusable",
				UsageLimit: 0,
			},
			expectedStatus:   http.StatusUnprocessableEntity,
			expectedResponse: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			apiHandler, am, done := buildApiBlackBoxWithDBState(t, "testdata/setup_keys.sql", nil)

			body, err := json.Marshal(tc.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}
			req := buildRequest(t, body, tc.requestType, tc.requestPath)

			recorder := httptest.NewRecorder()

			apiHandler.ServeHTTP(recorder, req)

			content, noResponseExpected := readResponse(t, recorder, tc.expectedStatus)
			if noResponseExpected {
				return
			}
			got := &api.SetupKey{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			validateCreatedKey(t, tc.expectedResponse, got)

			key, err := am.GetSetupKey(context.Background(), testAccountId, testUserId, got.Id)
			if err != nil {
				return
			}

			validateCreatedKey(t, tc.expectedResponse, toResponseBody(key))

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func buildApiBlackBoxWithDBState(t *testing.T, sqlFile string, expectedPeerUpdate *server.UpdateMessage) (http.Handler, server.AccountManager, chan struct{}) {
	store, cleanup, err := server.NewTestStoreFromSQL(context.Background(), sqlFile, t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	t.Cleanup(cleanup)

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())

	peersUpdateManager := server.NewPeersUpdateManager(nil)
	updMsg := peersUpdateManager.CreateChannel(context.Background(), testPeerId)
	done := make(chan struct{})
	go func() {
		if expectedPeerUpdate != nil {
			peerShouldReceiveUpdate(t, updMsg, expectedPeerUpdate)
		} else {
			peerShouldNotReceiveUpdate(t, updMsg)
		}
		close(done)
	}()

	geoMock := &geolocation.GeolocationMock{}
	validatorMock := server.MocIntegratedValidator{}
	am, err := server.BuildManager(context.Background(), store, peersUpdateManager, nil, "", "", &activity.InMemoryEventStore{}, geoMock, false, validatorMock, metrics)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	apiHandler, err := APIHandler(context.Background(), am, geoMock, &jwtclaims.JwtValidatorMock{}, metrics, AuthCfg{}, validatorMock)
	if err != nil {
		t.Fatalf("Failed to create API handler: %v", err)
	}

	return apiHandler, am, done
}

func buildRequest(t *testing.T, requestBody []byte, requestType, requestPath string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(requestType, requestPath, bytes.NewBuffer(requestBody))
	req.Header.Set("Authorization", "Bearer "+"my.dummy.token")

	return req
}

func readResponse(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int) ([]byte, bool) {
	t.Helper()

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if status := recorder.Code; status != expectedStatus {
		t.Fatalf("handler returned wrong status code: got %v want %v, content: %s",
			status, expectedStatus, string(content))
	}

	return content, expectedStatus != http.StatusOK
}

func validateCreatedKey(t *testing.T, expectedKey *api.SetupKey, got *api.SetupKey) {
	t.Helper()

	if got.Expires.After(time.Now().Add(-1*time.Minute)) && got.Expires.Before(time.Now().Add(expiresIn*time.Second)) {
		got.Expires = time.Time{}
		expectedKey.Expires = time.Time{}
	}

	if got.Id == "" {
		t.Error("Expected key to have an ID")
	}
	got.Id = ""

	if got.Key == "" {
		t.Error("Expected key to have a key")
	}
	got.Key = ""

	if got.UpdatedAt.After(time.Now().Add(-1*time.Minute)) && got.UpdatedAt.Before(time.Now().Add(+1*time.Minute)) {
		got.UpdatedAt = time.Time{}
		expectedKey.UpdatedAt = time.Time{}
	}

	assert.Equal(t, expectedKey, got)
}

func peerShouldNotReceiveUpdate(t *testing.T, updateMessage <-chan *server.UpdateMessage) {
	t.Helper()
	select {
	case msg := <-updateMessage:
		t.Errorf("Unexpected message received: %+v", msg)
	case <-time.After(500 * time.Millisecond):
		return
	}
}

func peerShouldReceiveUpdate(t *testing.T, updateMessage <-chan *server.UpdateMessage, expected *server.UpdateMessage) {
	t.Helper()

	select {
	case msg := <-updateMessage:
		if msg == nil {
			t.Errorf("Received nil update message, expected valid message")
		}
		assert.Equal(t, expected, msg)
	case <-time.After(500 * time.Millisecond):
		t.Error("Timed out waiting for update message")
	}
}
