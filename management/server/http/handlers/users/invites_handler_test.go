package users

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID   = "test-account-id"
	testUserID      = "test-user-id"
	testInviteID    = "test-invite-id"
	testInviteToken = "nbi_testtoken123456789012345678"
	testEmail       = "invite@example.com"
	testName        = "Test User"
)

func setupInvitesTestHandler(am *mock_server.MockAccountManager) *invitesHandler {
	return &invitesHandler{
		accountManager: am,
	}
}

func TestListInvites(t *testing.T) {
	now := time.Now().UTC()
	testInvites := []*types.UserInvite{
		{
			UserInfo: &types.UserInfo{
				ID:         "invite-1",
				Email:      "user1@example.com",
				Name:       "User One",
				Role:       "user",
				AutoGroups: []string{"group-1"},
			},
			InviteExpiresAt: now.Add(24 * time.Hour),
			InviteCreatedAt: now,
		},
		{
			UserInfo: &types.UserInfo{
				ID:         "invite-2",
				Email:      "user2@example.com",
				Name:       "User Two",
				Role:       "admin",
				AutoGroups: nil,
			},
			InviteExpiresAt: now.Add(-1 * time.Hour), // Expired
			InviteCreatedAt: now.Add(-48 * time.Hour),
		},
	}

	tt := []struct {
		name           string
		expectedStatus int
		mockFunc       func(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error)
		expectedCount  int
	}{
		{
			name:           "successful list",
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error) {
				return testInvites, nil
			},
			expectedCount: 2,
		},
		{
			name:           "empty list",
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error) {
				return []*types.UserInvite{}, nil
			},
			expectedCount: 0,
		},
		{
			name:           "permission denied",
			expectedStatus: http.StatusForbidden,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error) {
				return nil, status.NewPermissionDeniedError()
			},
			expectedCount: 0,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{
				ListUserInvitesFunc: tc.mockFunc,
			}
			handler := setupInvitesTestHandler(am)

			req := httptest.NewRequest(http.MethodGet, "/api/users/invites", nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			rr := httptest.NewRecorder()
			handler.listInvites(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK {
				var resp []api.UserInvite
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)
				assert.Len(t, resp, tc.expectedCount)
			}
		})
	}
}

func TestCreateInvite(t *testing.T) {
	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)

	tt := []struct {
		name           string
		requestBody    string
		expectedStatus int
		mockFunc       func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error)
	}{
		{
			name:           "successful create",
			requestBody:    `{"email":"test@example.com","name":"Test User","role":"user","auto_groups":["group-1"]}`,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				return &types.UserInvite{
					UserInfo: &types.UserInfo{
						ID:         testInviteID,
						Email:      invite.Email,
						Name:       invite.Name,
						Role:       invite.Role,
						AutoGroups: invite.AutoGroups,
						Status:     string(types.UserStatusInvited),
					},
					InviteToken:     testInviteToken,
					InviteExpiresAt: expiresAt,
				}, nil
			},
		},
		{
			name:           "successful create with custom expiration",
			requestBody:    `{"email":"test@example.com","name":"Test User","role":"admin","auto_groups":[],"expires_in":3600}`,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				assert.Equal(t, 3600, expiresIn)
				return &types.UserInvite{
					UserInfo: &types.UserInfo{
						ID:         testInviteID,
						Email:      invite.Email,
						Name:       invite.Name,
						Role:       invite.Role,
						AutoGroups: []string{},
						Status:     string(types.UserStatusInvited),
					},
					InviteToken:     testInviteToken,
					InviteExpiresAt: expiresAt,
				}, nil
			},
		},
		{
			name:           "user already exists",
			requestBody:    `{"email":"existing@example.com","name":"Existing User","role":"user","auto_groups":[]}`,
			expectedStatus: http.StatusConflict,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				return nil, status.Errorf(status.UserAlreadyExists, "user with this email already exists")
			},
		},
		{
			name:           "invite already exists",
			requestBody:    `{"email":"invited@example.com","name":"Invited User","role":"user","auto_groups":[]}`,
			expectedStatus: http.StatusConflict,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				return nil, status.Errorf(status.AlreadyExists, "invite already exists for this email")
			},
		},
		{
			name:           "permission denied",
			requestBody:    `{"email":"test@example.com","name":"Test User","role":"user","auto_groups":[]}`,
			expectedStatus: http.StatusForbidden,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				return nil, status.NewPermissionDeniedError()
			},
		},
		{
			name:           "embedded IDP not enabled",
			requestBody:    `{"email":"test@example.com","name":"Test User","role":"user","auto_groups":[]}`,
			expectedStatus: http.StatusPreconditionFailed,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				return nil, status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
			},
		},
		{
			name:           "local auth disabled",
			requestBody:    `{"email":"test@example.com","name":"Test User","role":"user","auto_groups":[]}`,
			expectedStatus: http.StatusPreconditionFailed,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
				return nil, status.Errorf(status.PreconditionFailed, "local user creation is disabled - use an external identity provider")
			},
		},
		{
			name:           "invalid JSON",
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
			mockFunc:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{
				CreateUserInviteFunc: tc.mockFunc,
			}
			handler := setupInvitesTestHandler(am)

			req := httptest.NewRequest(http.MethodPost, "/api/users/invites", bytes.NewBufferString(tc.requestBody))
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			rr := httptest.NewRecorder()
			handler.createInvite(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK {
				var resp api.UserInvite
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)
				assert.Equal(t, testInviteID, resp.Id)
				assert.NotNil(t, resp.InviteToken)
				assert.NotEmpty(t, *resp.InviteToken)
			}
		})
	}
}

func TestGetInviteInfo(t *testing.T) {
	now := time.Now().UTC()

	tt := []struct {
		name           string
		token          string
		expectedStatus int
		mockFunc       func(ctx context.Context, token string) (*types.UserInviteInfo, error)
	}{
		{
			name:           "successful get valid invite",
			token:          testInviteToken,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, token string) (*types.UserInviteInfo, error) {
				return &types.UserInviteInfo{
					Email:     testEmail,
					Name:      testName,
					ExpiresAt: now.Add(24 * time.Hour),
					Valid:     true,
					InvitedBy: "Admin User",
				}, nil
			},
		},
		{
			name:           "successful get expired invite",
			token:          testInviteToken,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, token string) (*types.UserInviteInfo, error) {
				return &types.UserInviteInfo{
					Email:     testEmail,
					Name:      testName,
					ExpiresAt: now.Add(-24 * time.Hour),
					Valid:     false,
					InvitedBy: "Admin User",
				}, nil
			},
		},
		{
			name:           "invite not found",
			token:          "nbi_invalidtoken1234567890123456",
			expectedStatus: http.StatusNotFound,
			mockFunc: func(ctx context.Context, token string) (*types.UserInviteInfo, error) {
				return nil, status.Errorf(status.NotFound, "invite not found")
			},
		},
		{
			name:           "invalid token format",
			token:          "invalid",
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc: func(ctx context.Context, token string) (*types.UserInviteInfo, error) {
				return nil, status.Errorf(status.InvalidArgument, "invalid invite token")
			},
		},
		{
			name:           "missing token",
			token:          "",
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{
				GetUserInviteInfoFunc: tc.mockFunc,
			}
			handler := setupInvitesTestHandler(am)

			req := httptest.NewRequest(http.MethodGet, "/api/users/invites/"+tc.token, nil)
			if tc.token != "" {
				req = mux.SetURLVars(req, map[string]string{"token": tc.token})
			}

			rr := httptest.NewRecorder()
			handler.getInviteInfo(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK {
				var resp api.UserInviteInfo
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)
				assert.Equal(t, testEmail, resp.Email)
				assert.Equal(t, testName, resp.Name)
			}
		})
	}
}

func TestAcceptInvite(t *testing.T) {
	tt := []struct {
		name           string
		token          string
		requestBody    string
		expectedStatus int
		mockFunc       func(ctx context.Context, token, password string) error
	}{
		{
			name:           "successful accept",
			token:          testInviteToken,
			requestBody:    `{"password":"SecurePass123!"}`,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, token, password string) error {
				return nil
			},
		},
		{
			name:           "invite not found",
			token:          "nbi_invalidtoken1234567890123456",
			requestBody:    `{"password":"SecurePass123!"}`,
			expectedStatus: http.StatusNotFound,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.NotFound, "invite not found")
			},
		},
		{
			name:           "invite expired",
			token:          testInviteToken,
			requestBody:    `{"password":"SecurePass123!"}`,
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.InvalidArgument, "invite has expired")
			},
		},
		{
			name:           "embedded IDP not enabled",
			token:          testInviteToken,
			requestBody:    `{"password":"SecurePass123!"}`,
			expectedStatus: http.StatusPreconditionFailed,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
			},
		},
		{
			name:           "local auth disabled",
			token:          testInviteToken,
			requestBody:    `{"password":"SecurePass123!"}`,
			expectedStatus: http.StatusPreconditionFailed,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.PreconditionFailed, "local user creation is disabled - use an external identity provider")
			},
		},
		{
			name:           "missing token",
			token:          "",
			requestBody:    `{"password":"SecurePass123!"}`,
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc:       nil,
		},
		{
			name:           "invalid JSON",
			token:          testInviteToken,
			requestBody:    `{invalid}`,
			expectedStatus: http.StatusBadRequest,
			mockFunc:       nil,
		},
		{
			name:           "password too short",
			token:          testInviteToken,
			requestBody:    `{"password":"Short1!"}`,
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.InvalidArgument, "password must be at least 8 characters long")
			},
		},
		{
			name:           "password missing digit",
			token:          testInviteToken,
			requestBody:    `{"password":"NoDigitPass!"}`,
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.InvalidArgument, "password must contain at least one digit")
			},
		},
		{
			name:           "password missing uppercase",
			token:          testInviteToken,
			requestBody:    `{"password":"nouppercase1!"}`,
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.InvalidArgument, "password must contain at least one uppercase letter")
			},
		},
		{
			name:           "password missing special character",
			token:          testInviteToken,
			requestBody:    `{"password":"NoSpecial123"}`,
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc: func(ctx context.Context, token, password string) error {
				return status.Errorf(status.InvalidArgument, "password must contain at least one special character")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{
				AcceptUserInviteFunc: tc.mockFunc,
			}
			handler := setupInvitesTestHandler(am)

			req := httptest.NewRequest(http.MethodPost, "/api/users/invites/"+tc.token+"/accept", bytes.NewBufferString(tc.requestBody))
			if tc.token != "" {
				req = mux.SetURLVars(req, map[string]string{"token": tc.token})
			}

			rr := httptest.NewRecorder()
			handler.acceptInvite(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK {
				var resp api.UserInviteAcceptResponse
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)
				assert.True(t, resp.Success)
			}
		})
	}
}

func TestRegenerateInvite(t *testing.T) {
	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)

	tt := []struct {
		name           string
		inviteID       string
		requestBody    string
		expectedStatus int
		mockFunc       func(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error)
	}{
		{
			name:           "successful regenerate with empty body",
			inviteID:       testInviteID,
			requestBody:    "",
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error) {
				assert.Equal(t, 0, expiresIn)
				return &types.UserInvite{
					UserInfo: &types.UserInfo{
						ID:    inviteID,
						Email: testEmail,
					},
					InviteToken:     "nbi_newtoken12345678901234567890",
					InviteExpiresAt: expiresAt,
				}, nil
			},
		},
		{
			name:           "successful regenerate with custom expiration",
			inviteID:       testInviteID,
			requestBody:    `{"expires_in":7200}`,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error) {
				assert.Equal(t, 7200, expiresIn)
				return &types.UserInvite{
					UserInfo: &types.UserInfo{
						ID:    inviteID,
						Email: testEmail,
					},
					InviteToken:     "nbi_newtoken12345678901234567890",
					InviteExpiresAt: expiresAt,
				}, nil
			},
		},
		{
			name:           "invite not found",
			inviteID:       "non-existent-invite",
			requestBody:    "",
			expectedStatus: http.StatusNotFound,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error) {
				return nil, status.Errorf(status.NotFound, "invite not found")
			},
		},
		{
			name:           "permission denied",
			inviteID:       testInviteID,
			requestBody:    "",
			expectedStatus: http.StatusForbidden,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error) {
				return nil, status.NewPermissionDeniedError()
			},
		},
		{
			name:           "missing invite ID",
			inviteID:       "",
			requestBody:    "",
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc:       nil,
		},
		{
			name:           "invalid JSON should return error",
			inviteID:       testInviteID,
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
			mockFunc:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{
				RegenerateUserInviteFunc: tc.mockFunc,
			}
			handler := setupInvitesTestHandler(am)

			var body io.Reader
			if tc.requestBody != "" {
				body = bytes.NewBufferString(tc.requestBody)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/users/invites/"+tc.inviteID+"/regenerate", body)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})
			if tc.inviteID != "" {
				req = mux.SetURLVars(req, map[string]string{"inviteId": tc.inviteID})
			}

			rr := httptest.NewRecorder()
			handler.regenerateInvite(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK {
				var resp api.UserInviteRegenerateResponse
				err := json.NewDecoder(rr.Body).Decode(&resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.InviteToken)
			}
		})
	}
}

func TestDeleteInvite(t *testing.T) {
	tt := []struct {
		name           string
		inviteID       string
		expectedStatus int
		mockFunc       func(ctx context.Context, accountID, initiatorUserID, inviteID string) error
	}{
		{
			name:           "successful delete",
			inviteID:       testInviteID,
			expectedStatus: http.StatusOK,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string) error {
				return nil
			},
		},
		{
			name:           "invite not found",
			inviteID:       "non-existent-invite",
			expectedStatus: http.StatusNotFound,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string) error {
				return status.Errorf(status.NotFound, "invite not found")
			},
		},
		{
			name:           "permission denied",
			inviteID:       testInviteID,
			expectedStatus: http.StatusForbidden,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string) error {
				return status.NewPermissionDeniedError()
			},
		},
		{
			name:           "embedded IDP not enabled",
			inviteID:       testInviteID,
			expectedStatus: http.StatusPreconditionFailed,
			mockFunc: func(ctx context.Context, accountID, initiatorUserID, inviteID string) error {
				return status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
			},
		},
		{
			name:           "missing invite ID",
			inviteID:       "",
			expectedStatus: http.StatusUnprocessableEntity,
			mockFunc:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{
				DeleteUserInviteFunc: tc.mockFunc,
			}
			handler := setupInvitesTestHandler(am)

			req := httptest.NewRequest(http.MethodDelete, "/api/users/invites/"+tc.inviteID, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})
			if tc.inviteID != "" {
				req = mux.SetURLVars(req, map[string]string{"inviteId": tc.inviteID})
			}

			rr := httptest.NewRecorder()
			handler.deleteInvite(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
		})
	}
}
