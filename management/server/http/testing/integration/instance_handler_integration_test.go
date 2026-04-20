//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// Test_Instance_GetStatus tests the unauthenticated GET /api/instance endpoint.
// This endpoint bypasses auth middleware. With nil idpManager (no embedded IDP),
// SetupRequired should be false.
func Test_Instance_GetStatus(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, false)

	// The /api/instance endpoint is unauthenticated (bypass path).
	// We still pass a token via BuildRequest but the bypass middleware skips auth.
	req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/instance", testing_tools.TestAdminId)
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	assert.Equal(t, http.StatusOK, recorder.Code, "Expected 200 OK for instance status endpoint, got %d: %s", recorder.Code, string(content))

	got := &api.InstanceStatus{}
	if err := json.Unmarshal(content, got); err != nil {
		t.Fatalf("Sent content is not in correct json format; %v", err)
	}

	// With nil idpManager (no embedded IDP configured), setup is not required.
	assert.Equal(t, false, got.SetupRequired, "Expected SetupRequired to be false when embedded IDP is not configured")
}

// Test_Instance_GetStatus_Unauthenticated verifies the endpoint works without any
// valid user token, since it is on the bypass path.
func Test_Instance_GetStatus_Unauthenticated(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, false)

	// Use an invalid token to confirm the bypass middleware skips auth
	req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/instance", testing_tools.InvalidToken)
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	assert.Equal(t, http.StatusOK, recorder.Code, "Expected 200 OK for unauthenticated instance status endpoint, got %d: %s", recorder.Code, string(content))

	got := &api.InstanceStatus{}
	if err := json.Unmarshal(content, got); err != nil {
		t.Fatalf("Sent content is not in correct json format; %v", err)
	}

	assert.Equal(t, false, got.SetupRequired)
}

// Test_Instance_GetVersionInfo tests the authenticated GET /api/instance/version endpoint.
func Test_Instance_GetVersionInfo(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get version info", func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, false)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/instance/version", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := &api.InstanceVersionInfo{}
			if err := json.Unmarshal(content, got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.NotEmpty(t, got.ManagementCurrentVersion, "Expected non-empty current version")
		})
	}
}

// Test_Instance_Setup tests the unauthenticated POST /api/setup endpoint.
// Since embedded IDP is not configured in the test environment, the setup
// endpoint should return an error (500 Internal Server Error) because the
// instance manager's CreateOwnerUser returns "embedded IDP is not enabled".
func Test_Instance_Setup(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, false)

	body, err := json.Marshal(&api.SetupRequest{
		Email:    "admin@test.com",
		Password: "securepassword123",
		Name:     "Admin User",
	})
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	// The /api/setup endpoint is unauthenticated (bypass path).
	req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/setup", testing_tools.TestAdminId)
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Without embedded IDP, CreateOwnerUser returns a plain error (not a status error),
	// which the handler maps to 500 Internal Server Error.
	assert.Equal(t, http.StatusInternalServerError, recorder.Code,
		"Expected 500 when embedded IDP is not configured, got %d: %s", recorder.Code, string(content))
}

// Test_Instance_Setup_Unauthenticated verifies the setup endpoint works (reaches
// the handler) even with an invalid token, since it is on the bypass path.
func Test_Instance_Setup_Unauthenticated(t *testing.T) {
	apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, false)

	body, err := json.Marshal(&api.SetupRequest{
		Email:    "admin@test.com",
		Password: "securepassword123",
		Name:     "Admin User",
	})
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/setup", testing_tools.InvalidToken)
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Even with an invalid token, the bypass middleware skips auth and the handler runs.
	// Without embedded IDP, it returns 500.
	assert.Equal(t, http.StatusInternalServerError, recorder.Code,
		"Expected 500 when embedded IDP is not configured, got %d: %s", recorder.Code, string(content))
}
