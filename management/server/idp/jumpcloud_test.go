package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

func TestNewJumpCloudManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          JumpCloudClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := JumpCloudClientConfig{
		APIToken: "test123",
	}

	testCase1 := test{
		name:                 "Good Configuration",
		inputConfig:          defaultTestConfig,
		assertErrFunc:        require.NoError,
		assertErrFuncMessage: "shouldn't return error",
	}

	testCase2Config := defaultTestConfig
	testCase2Config.APIToken = ""

	testCase2 := test{
		name:                 "Missing APIToken Configuration",
		inputConfig:          testCase2Config,
		assertErrFunc:        require.Error,
		assertErrFuncMessage: "should return error when field empty",
	}

	for _, testCase := range []test{testCase1, testCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewJumpCloudManager(testCase.inputConfig, &telemetry.MockAppMetrics{})
			testCase.assertErrFunc(t, err, testCase.assertErrFuncMessage)
		})
	}
}

func TestJumpCloudGetUserDataByID(t *testing.T) {
	userResponse := jumpCloudUser{
		ID:         "user123",
		Email:      "test@example.com",
		Firstname:  "John",
		Middlename: "",
		Lastname:   "Doe",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/systemusers/user123", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "test-api-key", r.Header.Get("x-api-key"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userResponse)
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	userData, err := manager.GetUserDataByID(context.Background(), "user123", AppMetadata{WTAccountID: "acc1"})
	require.NoError(t, err)

	assert.Equal(t, "user123", userData.ID)
	assert.Equal(t, "test@example.com", userData.Email)
	assert.Equal(t, "John  Doe", userData.Name)
	assert.Equal(t, "acc1", userData.AppMetadata.WTAccountID)
}

func TestJumpCloudGetAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/search/systemusers", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var reqBody map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))
		assert.Contains(t, reqBody, "limit")
		assert.Contains(t, reqBody, "skip")

		resp := jumpCloudUserList{
			Results: []jumpCloudUser{
				{ID: "u1", Email: "a@test.com", Firstname: "Alice", Lastname: "Smith"},
				{ID: "u2", Email: "b@test.com", Firstname: "Bob", Lastname: "Jones"},
			},
			TotalCount: 2,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	users, err := manager.GetAccount(context.Background(), "testAccount")
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "testAccount", users[0].AppMetadata.WTAccountID)
	assert.Equal(t, "testAccount", users[1].AppMetadata.WTAccountID)
}

func TestJumpCloudGetAllAccounts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jumpCloudUserList{
			Results: []jumpCloudUser{
				{ID: "u1", Email: "a@test.com", Firstname: "Alice"},
				{ID: "u2", Email: "b@test.com", Firstname: "Bob"},
			},
			TotalCount: 2,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	indexedUsers, err := manager.GetAllAccounts(context.Background())
	require.NoError(t, err)
	assert.Len(t, indexedUsers[UnsetAccountID], 2)
}

func TestJumpCloudGetAllAccountsPagination(t *testing.T) {
	totalUsers := 250
	allUsers := make([]jumpCloudUser, totalUsers)
	for i := range allUsers {
		allUsers[i] = jumpCloudUser{
			ID:        fmt.Sprintf("u%d", i),
			Email:     fmt.Sprintf("user%d@test.com", i),
			Firstname: fmt.Sprintf("User%d", i),
		}
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]int
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&reqBody))

		limit := reqBody["limit"]
		skip := reqBody["skip"]
		requestCount++

		end := skip + limit
		if end > totalUsers {
			end = totalUsers
		}

		resp := jumpCloudUserList{
			Results:    allUsers[skip:end],
			TotalCount: totalUsers,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	indexedUsers, err := manager.GetAllAccounts(context.Background())
	require.NoError(t, err)
	assert.Len(t, indexedUsers[UnsetAccountID], totalUsers)
	assert.Equal(t, 3, requestCount, "should require 3 pages for 250 users at page size 100")
}

func TestJumpCloudGetUserByEmail(t *testing.T) {
	searchResponse := jumpCloudUserList{
		Results: []jumpCloudUser{
			{ID: "u1", Email: "alice@test.com", Firstname: "Alice", Lastname: "Smith"},
		},
		TotalCount: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/search/systemusers", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), "alice@test.com")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(searchResponse)
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	users, err := manager.GetUserByEmail(context.Background(), "alice@test.com")
	require.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, "alice@test.com", users[0].Email)
}

func TestJumpCloudDeleteUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/systemusers/user123", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "test-api-key", r.Header.Get("x-api-key"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"_id": "user123"})
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	err := manager.DeleteUser(context.Background(), "user123")
	require.NoError(t, err)
}

func TestJumpCloudAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	manager := newTestJumpCloudManager(t, server.URL)

	_, err := manager.GetUserDataByID(context.Background(), "user123", AppMetadata{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestParseJumpCloudUser(t *testing.T) {
	user := jumpCloudUser{
		ID:         "abc123",
		Email:      "test@example.com",
		Firstname:  "John",
		Middlename: "M",
		Lastname:   "Doe",
	}

	userData := parseJumpCloudUser(user)
	assert.Equal(t, "abc123", userData.ID)
	assert.Equal(t, "test@example.com", userData.Email)
	assert.Equal(t, "John M Doe", userData.Name)
}

func newTestJumpCloudManager(t *testing.T, apiBase string) *JumpCloudManager {
	t.Helper()
	return &JumpCloudManager{
		apiBase:    apiBase,
		apiToken:   "test-api-key",
		httpClient: http.DefaultClient,
		helper:     JsonParser{},
		appMetrics: nil,
	}
}
