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

	newKeyName = "newKey"
	expiresIn  = 3600

	existingKeyName = "existingKey"
)

func Test_SetupKeys_Create_Success(t *testing.T) {
	tt := []struct {
		name             string
		expectedStatus   int
		expectedSetupKey *api.SetupKey
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
			expectedSetupKey: &api.SetupKey{
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
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			store, cleanup, err := server.NewTestStoreFromSQL(context.Background(), "testdata/setup_keys.sql", t.TempDir())
			if err != nil {
				t.Fatalf("Failed to create test store: %v", err)
			}
			t.Cleanup(cleanup)

			metrics, err := telemetry.NewDefaultAppMetrics(context.Background())

			peersUpdateManager := &server.PeersUpdateManager{}
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

			body, err := json.Marshal(tc.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, bytes.NewBuffer(body))
			req.Header.Set("Authorization", "Bearer "+"my.dummy.token")

			apiHandler.ServeHTTP(recorder, req)

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

			got := &api.SetupKey{}
			if err = json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			validateCreatedKey(t, tc.expectedSetupKey, got)

			key, err := am.GetSetupKey(context.Background(), testAccountId, testUserId, got.Id)
			if err != nil {
				return
			}

			validateCreatedKey(t, tc.expectedSetupKey, toResponseBody(key))
		})
	}
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
