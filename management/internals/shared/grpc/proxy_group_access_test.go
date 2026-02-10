package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/server/types"
)

type mockReverseProxyManager struct {
	proxiesByAccount map[string][]*reverseproxy.ReverseProxy
	err              error
}

func (m *mockReverseProxyManager) GetAccountReverseProxies(ctx context.Context, accountID string) ([]*reverseproxy.ReverseProxy, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.proxiesByAccount[accountID], nil
}

func (m *mockReverseProxyManager) GetGlobalReverseProxies(ctx context.Context) ([]*reverseproxy.ReverseProxy, error) {
	return nil, nil
}

func (m *mockReverseProxyManager) GetAllReverseProxies(ctx context.Context, accountID, userID string) ([]*reverseproxy.ReverseProxy, error) {
	return nil, nil
}

func (m *mockReverseProxyManager) GetReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) (*reverseproxy.ReverseProxy, error) {
	return nil, nil
}

func (m *mockReverseProxyManager) CreateReverseProxy(ctx context.Context, accountID, userID string, rp *reverseproxy.ReverseProxy) (*reverseproxy.ReverseProxy, error) {
	return nil, nil
}

func (m *mockReverseProxyManager) UpdateReverseProxy(ctx context.Context, accountID, userID string, rp *reverseproxy.ReverseProxy) (*reverseproxy.ReverseProxy, error) {
	return nil, nil
}

func (m *mockReverseProxyManager) DeleteReverseProxy(ctx context.Context, accountID, userID, reverseProxyID string) error {
	return nil
}

func (m *mockReverseProxyManager) SetCertificateIssuedAt(ctx context.Context, accountID, reverseProxyID string) error {
	return nil
}

func (m *mockReverseProxyManager) SetStatus(ctx context.Context, accountID, reverseProxyID string, status reverseproxy.ProxyStatus) error {
	return nil
}

func (m *mockReverseProxyManager) ReloadAllReverseProxiesForAccount(ctx context.Context, accountID string) error {
	return nil
}

func (m *mockReverseProxyManager) ReloadReverseProxy(ctx context.Context, accountID, reverseProxyID string) error {
	return nil
}

func (m *mockReverseProxyManager) GetProxyByID(ctx context.Context, accountID, reverseProxyID string) (*reverseproxy.ReverseProxy, error) {
	return nil, nil
}

type mockUsersManager struct {
	users map[string]*types.User
	err   error
}

func (m *mockUsersManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	user, ok := m.users[userID]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func TestValidateUserGroupAccess(t *testing.T) {
	tests := []struct {
		name             string
		domain           string
		userID           string
		proxiesByAccount map[string][]*reverseproxy.ReverseProxy
		users            map[string]*types.User
		proxyErr         error
		userErr          error
		expectErr        bool
		expectErrMsg     string
	}{
		{
			name:   "user not found",
			domain: "app.example.com",
			userID: "unknown-user",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{Domain: "app.example.com", AccountID: "account1"}},
			},
			users:        map[string]*types.User{},
			expectErr:    true,
			expectErrMsg: "user not found",
		},
		{
			name:             "proxy not found in user's account",
			domain:           "app.example.com",
			userID:           "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr:    true,
			expectErrMsg: "reverse proxy not found",
		},
		{
			name:   "proxy exists in different account - not accessible",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account2": {{Domain: "app.example.com", AccountID: "account2"}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr:    true,
			expectErrMsg: "reverse proxy not found",
		},
		{
			name:   "no bearer auth configured - same account allows access",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{Domain: "app.example.com", AccountID: "account1", Auth: reverseproxy.AuthConfig{}}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr: false,
		},
		{
			name:   "bearer auth disabled - same account allows access",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: reverseproxy.AuthConfig{
						BearerAuth: &reverseproxy.BearerAuthConfig{Enabled: false},
					},
				}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr: false,
		},
		{
			name:   "bearer auth enabled but no groups configured - same account allows access",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: reverseproxy.AuthConfig{
						BearerAuth: &reverseproxy.BearerAuthConfig{
							Enabled:            true,
							DistributionGroups: []string{},
						},
					},
				}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr: false,
		},
		{
			name:   "user not in allowed groups",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: reverseproxy.AuthConfig{
						BearerAuth: &reverseproxy.BearerAuthConfig{
							Enabled:            true,
							DistributionGroups: []string{"group1", "group2"},
						},
					},
				}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1", AutoGroups: []string{"group3", "group4"}},
			},
			expectErr:    true,
			expectErrMsg: "not in allowed groups",
		},
		{
			name:   "user in one of the allowed groups - allow access",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: reverseproxy.AuthConfig{
						BearerAuth: &reverseproxy.BearerAuthConfig{
							Enabled:            true,
							DistributionGroups: []string{"group1", "group2"},
						},
					},
				}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1", AutoGroups: []string{"group2", "group3"}},
			},
			expectErr: false,
		},
		{
			name:   "user in all allowed groups - allow access",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: reverseproxy.AuthConfig{
						BearerAuth: &reverseproxy.BearerAuthConfig{
							Enabled:            true,
							DistributionGroups: []string{"group1", "group2"},
						},
					},
				}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1", AutoGroups: []string{"group1", "group2", "group3"}},
			},
			expectErr: false,
		},
		{
			name:             "proxy manager error",
			domain:           "app.example.com",
			userID:           "user1",
			proxiesByAccount: nil,
			proxyErr:         errors.New("database error"),
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr:    true,
			expectErrMsg: "get account reverse proxies",
		},
		{
			name:   "multiple proxies in account - finds correct one",
			domain: "app2.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {
					{Domain: "app1.example.com", AccountID: "account1"},
					{Domain: "app2.example.com", AccountID: "account1", Auth: reverseproxy.AuthConfig{}},
					{Domain: "app3.example.com", AccountID: "account1"},
				},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &ProxyServiceServer{
				reverseProxyManager: &mockReverseProxyManager{
					proxiesByAccount: tt.proxiesByAccount,
					err:              tt.proxyErr,
				},
				usersManager: &mockUsersManager{
					users: tt.users,
					err:   tt.userErr,
				},
			}

			err := server.ValidateUserGroupAccess(context.Background(), tt.domain, tt.userID)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetAccountProxyByDomain(t *testing.T) {
	tests := []struct {
		name             string
		accountID        string
		domain           string
		proxiesByAccount map[string][]*reverseproxy.ReverseProxy
		err              error
		expectProxy      bool
		expectErr        bool
	}{
		{
			name:      "proxy found",
			accountID: "account1",
			domain:    "app.example.com",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {
					{Domain: "other.example.com", AccountID: "account1"},
					{Domain: "app.example.com", AccountID: "account1"},
				},
			},
			expectProxy: true,
			expectErr:   false,
		},
		{
			name:      "proxy not found in account",
			accountID: "account1",
			domain:    "unknown.example.com",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{
				"account1": {{Domain: "app.example.com", AccountID: "account1"}},
			},
			expectProxy: false,
			expectErr:   true,
		},
		{
			name:             "empty proxy list for account",
			accountID:        "account1",
			domain:           "app.example.com",
			proxiesByAccount: map[string][]*reverseproxy.ReverseProxy{},
			expectProxy:      false,
			expectErr:        true,
		},
		{
			name:             "manager error",
			accountID:        "account1",
			domain:           "app.example.com",
			proxiesByAccount: nil,
			err:              errors.New("database error"),
			expectProxy:      false,
			expectErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &ProxyServiceServer{
				reverseProxyManager: &mockReverseProxyManager{
					proxiesByAccount: tt.proxiesByAccount,
					err:              tt.err,
				},
			}

			proxy, err := server.getAccountProxyByDomain(context.Background(), tt.accountID, tt.domain)

			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, proxy)
			} else {
				require.NoError(t, err)
				require.NotNil(t, proxy)
				assert.Equal(t, tt.domain, proxy.Domain)
			}
		})
	}
}
