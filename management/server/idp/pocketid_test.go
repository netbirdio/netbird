package idp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

func TestNewPocketIdManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          PocketIdClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
	}

	defaultTestConfig := PocketIdClientConfig{
		APIToken:           "api_token",
		ManagementEndpoint: "http://localhost",
	}

	tests := []test{
		{
			name:                 "Good Configuration",
			inputConfig:          defaultTestConfig,
			assertErrFunc:        require.NoError,
			assertErrFuncMessage: "shouldn't return error",
		},
		{
			name: "Missing ManagementEndpoint",
			inputConfig: PocketIdClientConfig{
				APIToken:           defaultTestConfig.APIToken,
				ManagementEndpoint: "",
			},
			assertErrFunc:        require.Error,
			assertErrFuncMessage: "should return error when field empty",
		},
		{
			name: "Missing APIToken",
			inputConfig: PocketIdClientConfig{
				APIToken:           "",
				ManagementEndpoint: defaultTestConfig.ManagementEndpoint,
			},
			assertErrFunc:        require.Error,
			assertErrFuncMessage: "should return error when field empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPocketIdManager(tc.inputConfig, &telemetry.MockAppMetrics{})
			tc.assertErrFunc(t, err, tc.assertErrFuncMessage)
		})
	}
}

func TestPocketID_GetUserDataByID(t *testing.T) {
	client := &mockHTTPClient{code: 200, resBody: `{"id":"u1","email":"user1@example.com","displayName":"User One"}`}

	mgr, err := NewPocketIdManager(PocketIdClientConfig{APIToken: "tok", ManagementEndpoint: "http://localhost"}, nil)
	require.NoError(t, err)
	mgr.httpClient = client

	md := AppMetadata{WTAccountID: "acc1"}
	got, err := mgr.GetUserDataByID(context.Background(), "u1", md)
	require.NoError(t, err)
	assert.Equal(t, "u1", got.ID)
	assert.Equal(t, "user1@example.com", got.Email)
	assert.Equal(t, "User One", got.Name)
	assert.Equal(t, "acc1", got.AppMetadata.WTAccountID)
}

func TestPocketID_GetAccount_WithPagination(t *testing.T) {
	// Single page response with two users
	client := &mockHTTPClient{code: 200, resBody: `{"data":[{"id":"u1","email":"e1","displayName":"n1"},{"id":"u2","email":"e2","displayName":"n2"}],"pagination":{"currentPage":1,"itemsPerPage":100,"totalItems":2,"totalPages":1}}`}

	mgr, err := NewPocketIdManager(PocketIdClientConfig{APIToken: "tok", ManagementEndpoint: "http://localhost"}, nil)
	require.NoError(t, err)
	mgr.httpClient = client

	users, err := mgr.GetAccount(context.Background(), "accX")
	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "u1", users[0].ID)
	assert.Equal(t, "accX", users[0].AppMetadata.WTAccountID)
	assert.Equal(t, "u2", users[1].ID)
}

func TestPocketID_GetAllAccounts_WithPagination(t *testing.T) {
	client := &mockHTTPClient{code: 200, resBody: `{"data":[{"id":"u1","email":"e1","displayName":"n1"},{"id":"u2","email":"e2","displayName":"n2"}],"pagination":{"currentPage":1,"itemsPerPage":100,"totalItems":2,"totalPages":1}}`}

	mgr, err := NewPocketIdManager(PocketIdClientConfig{APIToken: "tok", ManagementEndpoint: "http://localhost"}, nil)
	require.NoError(t, err)
	mgr.httpClient = client

	accounts, err := mgr.GetAllAccounts(context.Background())
	require.NoError(t, err)
	require.Len(t, accounts[UnsetAccountID], 2)
}

func TestPocketID_CreateUser(t *testing.T) {
	client := &mockHTTPClient{code: 201, resBody: `{"id":"newid","email":"new@example.com","displayName":"New User"}`}

	mgr, err := NewPocketIdManager(PocketIdClientConfig{APIToken: "tok", ManagementEndpoint: "http://localhost"}, nil)
	require.NoError(t, err)
	mgr.httpClient = client

	ud, err := mgr.CreateUser(context.Background(), "new@example.com", "New User", "acc1", "inviter@example.com")
	require.NoError(t, err)
	assert.Equal(t, "newid", ud.ID)
	assert.Equal(t, "new@example.com", ud.Email)
	assert.Equal(t, "New User", ud.Name)
	assert.Equal(t, "acc1", ud.AppMetadata.WTAccountID)
	if assert.NotNil(t, ud.AppMetadata.WTPendingInvite) {
		assert.True(t, *ud.AppMetadata.WTPendingInvite)
	}
	assert.Equal(t, "inviter@example.com", ud.AppMetadata.WTInvitedBy)
}

func TestPocketID_InviteAndDeleteUser(t *testing.T) {
	// Same mock for both calls; returns OK with empty JSON
	client := &mockHTTPClient{code: 200, resBody: `{}`}

	mgr, err := NewPocketIdManager(PocketIdClientConfig{APIToken: "tok", ManagementEndpoint: "http://localhost"}, nil)
	require.NoError(t, err)
	mgr.httpClient = client

	err = mgr.InviteUserByID(context.Background(), "u1")
	require.NoError(t, err)

	err = mgr.DeleteUser(context.Background(), "u1")
	require.NoError(t, err)
}
