//go:build component

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
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
	testAccountId = "testAccountId"
	testPeerId    = "testPeerId"
	testGroupId   = "testGroupId"
	testKeyId     = "testKeyId"

	testUserId         = "testUserId"
	testAdminId        = "testAdminId"
	testOwnerId        = "testOwnerId"
	testServiceUserId  = "testServiceUserId"
	testServiceAdminId = "testServiceAdminId"
	blockedUserId      = "blockedUserId"
	otherUserId        = "otherUserId"
	invalidToken       = "invalidToken"

	newKeyName   = "newKey"
	newGroupId   = "newGroupId"
	expiresIn    = 3600
	revokedKeyId = "revokedKeyId"
	expiredKeyId = "expiredKeyId"

	existingKeyName = "existingKey"
)

func Test_SetupKeys_Create(t *testing.T) {
	truePointer := true

	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         blockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         otherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         invalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name             string
		expectedStatus   int
		expectedResponse *api.SetupKey
		requestBody      *api.CreateSetupKeyRequest
		requestType      string
		requestPath      string
		userId           string
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
				AutoGroups: []string{testGroupId},
				ExpiresIn:  expiresIn,
				Name:       newKeyName,
				Type:       "reusable",
				UsageLimit: 1,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
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
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, done := buildApiBlackBoxWithDBState(t, "testdata/setup_keys.sql", nil)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
				req := buildRequest(t, body, tc.requestType, tc.requestPath, user.userId)

				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := readResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
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
}

func Test_SetupKeys_Update(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         blockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         otherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         invalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name             string
		expectedStatus   int
		expectedResponse *api.SetupKey
		requestBody      *api.SetupKeyRequest
		requestType      string
		requestPath      string
		requestId        string
	}{
		{
			name:        "Add existing Group to existing Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   testKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId, newGroupId},
				Revoked:    false,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId, newGroupId},
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
			name:        "Add non-existing Group to existing Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   testKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId, "someGroupId"},
				Revoked:    false,
			},
			expectedStatus:   http.StatusUnprocessableEntity,
			expectedResponse: nil,
		},
		{
			name:        "Add existing Group to non-existing Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   "someId",
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId, newGroupId},
				Revoked:    false,
			},
			expectedStatus:   http.StatusNotFound,
			expectedResponse: nil,
		},
		{
			name:        "Remove existing Group from existing Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   testKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{},
				Revoked:    false,
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
			name:        "Remove existing Group to non-existing Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   "someID",
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{},
				Revoked:    false,
			},
			expectedStatus:   http.StatusNotFound,
			expectedResponse: nil,
		},
		{
			name:        "Revoke existing valid Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   testKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId},
				Revoked:    true,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    true,
				State:      "revoked",
				Type:       "one-off",
				UpdatedAt:  time.Now(),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      false,
			},
		},
		{
			name:        "Revoke existing revoked Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   revokedKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId},
				Revoked:    true,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    true,
				State:      "revoked",
				Type:       "reusable",
				UpdatedAt:  time.Now(),
				UsageLimit: 3,
				UsedTimes:  0,
				Valid:      false,
			},
		},
		{
			name:        "Un-Revoke existing revoked Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   revokedKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId},
				Revoked:    false,
			},
			expectedStatus:   http.StatusUnprocessableEntity,
			expectedResponse: nil,
		},
		{
			name:        "Revoke existing expired Setup Key",
			requestType: http.MethodPut,
			requestPath: "/api/setup-keys/{id}",
			requestId:   expiredKeyId,
			requestBody: &api.SetupKeyRequest{
				AutoGroups: []string{testGroupId},
				Revoked:    true,
			},
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  true,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    true,
				State:      "expired",
				Type:       "reusable",
				UpdatedAt:  time.Now(),
				UsageLimit: 5,
				UsedTimes:  1,
				Valid:      false,
			},
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(tc.name, func(t *testing.T) {
				apiHandler, am, done := buildApiBlackBoxWithDBState(t, "testdata/setup_keys.sql", nil)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := buildRequest(t, body, tc.requestType, strings.Replace(tc.requestPath, "{id}", tc.requestId, 1), user.userId)

				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := readResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
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
}

func Test_SetupKeys_Get(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         blockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         otherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         invalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name             string
		expectedStatus   int
		expectedResponse *api.SetupKey
		requestType      string
		requestPath      string
		requestId        string
	}{
		{
			name:           "Get existing valid Setup Key",
			requestType:    http.MethodGet,
			requestPath:    "/api/setup-keys/{id}",
			requestId:      testKeyId,
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "one-off",
				UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:           "Get existing expired Setup Key",
			requestType:    http.MethodGet,
			requestPath:    "/api/setup-keys/{id}",
			requestId:      expiredKeyId,
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  true,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    false,
				State:      "expired",
				Type:       "reusable",
				UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
				UsageLimit: 5,
				UsedTimes:  1,
				Valid:      false,
			},
		},
		{
			name:           "Get existing revoked Setup Key",
			requestType:    http.MethodGet,
			requestPath:    "/api/setup-keys/{id}",
			requestId:      revokedKeyId,
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    true,
				State:      "revoked",
				Type:       "reusable",
				UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
				UsageLimit: 3,
				UsedTimes:  0,
				Valid:      false,
			},
		},
		{
			name:             "Get non-existing Setup Key",
			requestType:      http.MethodGet,
			requestPath:      "/api/setup-keys/{id}",
			requestId:        "someId",
			expectedStatus:   http.StatusNotFound,
			expectedResponse: nil,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(tc.name, func(t *testing.T) {
				apiHandler, am, done := buildApiBlackBoxWithDBState(t, "testdata/setup_keys.sql", nil)

				req := buildRequest(t, []byte{}, tc.requestType, strings.Replace(tc.requestPath, "{id}", tc.requestId, 1), user.userId)

				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, noResponseExpected := readResponse(t, recorder, tc.expectedStatus, user.expectResponse)
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
}

func Test_SetupKeys_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         blockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         otherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         invalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name             string
		expectedStatus   int
		expectedResponse []*api.SetupKey
		requestType      string
		requestPath      string
	}{
		{
			name:           "Get all Setup Keys",
			requestType:    http.MethodGet,
			requestPath:    "/api/setup-keys",
			expectedStatus: http.StatusOK,
			expectedResponse: []*api.SetupKey{
				{
					AutoGroups: []string{testGroupId},
					Ephemeral:  false,
					Expires:    time.Time{},
					Id:         "",
					Key:        "",
					LastUsed:   time.Time{},
					Name:       existingKeyName,
					Revoked:    false,
					State:      "valid",
					Type:       "one-off",
					UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
					UsageLimit: 1,
					UsedTimes:  0,
					Valid:      true,
				},
				{
					AutoGroups: []string{testGroupId},
					Ephemeral:  false,
					Expires:    time.Time{},
					Id:         "",
					Key:        "",
					LastUsed:   time.Time{},
					Name:       existingKeyName,
					Revoked:    true,
					State:      "revoked",
					Type:       "reusable",
					UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
					UsageLimit: 3,
					UsedTimes:  0,
					Valid:      false,
				},
				{
					AutoGroups: []string{testGroupId},
					Ephemeral:  true,
					Expires:    time.Time{},
					Id:         "",
					Key:        "",
					LastUsed:   time.Time{},
					Name:       existingKeyName,
					Revoked:    false,
					State:      "expired",
					Type:       "reusable",
					UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
					UsageLimit: 5,
					UsedTimes:  1,
					Valid:      false,
				},
			},
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(tc.name, func(t *testing.T) {
				apiHandler, am, done := buildApiBlackBoxWithDBState(t, "testdata/setup_keys.sql", nil)

				req := buildRequest(t, []byte{}, tc.requestType, tc.requestPath, user.userId)

				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := readResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}
				got := []api.SetupKey{}
				if err := json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}

				sort.Slice(got, func(i, j int) bool {
					return got[i].UsageLimit < got[j].UsageLimit
				})

				sort.Slice(tc.expectedResponse, func(i, j int) bool {
					return tc.expectedResponse[i].UsageLimit < tc.expectedResponse[j].UsageLimit
				})

				for i, _ := range tc.expectedResponse {
					validateCreatedKey(t, tc.expectedResponse[i], &got[i])

					key, err := am.GetSetupKey(context.Background(), testAccountId, testUserId, got[i].Id)
					if err != nil {
						return
					}

					validateCreatedKey(t, tc.expectedResponse[i], toResponseBody(key))
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_SetupKeys_Delete(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         blockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         otherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         invalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name             string
		expectedStatus   int
		expectedResponse *api.SetupKey
		requestType      string
		requestPath      string
		requestId        string
	}{
		{
			name:           "Delete existing valid Setup Key",
			requestType:    http.MethodDelete,
			requestPath:    "/api/setup-keys/{id}",
			requestId:      testKeyId,
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    false,
				State:      "valid",
				Type:       "one-off",
				UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
				UsageLimit: 1,
				UsedTimes:  0,
				Valid:      true,
			},
		},
		{
			name:           "Delete existing expired Setup Key",
			requestType:    http.MethodDelete,
			requestPath:    "/api/setup-keys/{id}",
			requestId:      expiredKeyId,
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  true,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    false,
				State:      "expired",
				Type:       "reusable",
				UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
				UsageLimit: 5,
				UsedTimes:  1,
				Valid:      false,
			},
		},
		{
			name:           "Delete existing revoked Setup Key",
			requestType:    http.MethodDelete,
			requestPath:    "/api/setup-keys/{id}",
			requestId:      revokedKeyId,
			expectedStatus: http.StatusOK,
			expectedResponse: &api.SetupKey{
				AutoGroups: []string{testGroupId},
				Ephemeral:  false,
				Expires:    time.Time{},
				Id:         "",
				Key:        "",
				LastUsed:   time.Time{},
				Name:       existingKeyName,
				Revoked:    true,
				State:      "revoked",
				Type:       "reusable",
				UpdatedAt:  time.Date(2021, time.August, 19, 20, 46, 20, 5936822, time.Local),
				UsageLimit: 3,
				UsedTimes:  0,
				Valid:      false,
			},
		},
		{
			name:             "Delete non-existing Setup Key",
			requestType:      http.MethodDelete,
			requestPath:      "/api/setup-keys/{id}",
			requestId:        "someId",
			expectedStatus:   http.StatusNotFound,
			expectedResponse: nil,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(tc.name, func(t *testing.T) {
				apiHandler, am, done := buildApiBlackBoxWithDBState(t, "testdata/setup_keys.sql", nil)

				req := buildRequest(t, []byte{}, tc.requestType, strings.Replace(tc.requestPath, "{id}", tc.requestId, 1), user.userId)

				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := readResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}
				got := &api.SetupKey{}
				if err := json.Unmarshal(content, &got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}

				_, err := am.GetSetupKey(context.Background(), testAccountId, testUserId, got.Id)
				assert.Errorf(t, err, "Expected error when trying to get deleted key")

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
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

func buildRequest(t *testing.T, requestBody []byte, requestType, requestPath, user string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(requestType, requestPath, bytes.NewBuffer(requestBody))
	req.Header.Set("Authorization", "Bearer "+user)

	return req
}

func readResponse(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectResponse bool) ([]byte, bool) {
	t.Helper()

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !expectResponse {
		return nil, false
	}

	if status := recorder.Code; status != expectedStatus {
		t.Fatalf("handler returned wrong status code: got %v want %v, content: %s",
			status, expectedStatus, string(content))
	}

	return content, expectedStatus == http.StatusOK
}

func validateCreatedKey(t *testing.T, expectedKey *api.SetupKey, got *api.SetupKey) {
	t.Helper()

	if got.Expires.After(time.Now().Add(-1*time.Minute)) && got.Expires.Before(time.Now().Add(expiresIn*time.Second)) ||
		got.Expires.After(time.Date(2300, 01, 01, 0, 0, 0, 0, time.Local)) ||
		got.Expires.Before(time.Date(1950, 01, 01, 0, 0, 0, 0, time.Local)) {
		got.Expires = time.Time{}
		expectedKey.Expires = time.Time{}
	}

	if got.Id == "" {
		t.Fatalf("Expected key to have an ID")
	}
	got.Id = ""

	if got.Key == "" {
		t.Fatalf("Expected key to have a key")
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
