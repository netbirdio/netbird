package grpc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type mockReverseProxyManager struct {
	proxiesByAccount map[string][]*service.Service
	err              error
}

func (m *mockReverseProxyManager) DeleteAllServices(ctx context.Context, accountID, userID string) error {
	return nil
}

func (m *mockReverseProxyManager) GetAccountServices(ctx context.Context, accountID string) ([]*service.Service, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.proxiesByAccount[accountID], nil
}

func (m *mockReverseProxyManager) GetGlobalServices(ctx context.Context) ([]*service.Service, error) {
	return nil, nil
}

func (m *mockReverseProxyManager) GetAllServices(ctx context.Context, accountID, userID string) ([]*service.Service, error) {
	return []*service.Service{}, nil
}

func (m *mockReverseProxyManager) GetService(ctx context.Context, accountID, userID, reverseProxyID string) (*service.Service, error) {
	return &service.Service{}, nil
}

func (m *mockReverseProxyManager) CreateService(ctx context.Context, accountID, userID string, rp *service.Service) (*service.Service, error) {
	return &service.Service{}, nil
}

func (m *mockReverseProxyManager) UpdateService(ctx context.Context, accountID, userID string, rp *service.Service) (*service.Service, error) {
	return &service.Service{}, nil
}

func (m *mockReverseProxyManager) DeleteService(ctx context.Context, accountID, userID, reverseProxyID string) error {
	return nil
}

func (m *mockReverseProxyManager) DeleteAccountCluster(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockReverseProxyManager) SetCertificateIssuedAt(ctx context.Context, accountID, reverseProxyID string) error {
	return nil
}

func (m *mockReverseProxyManager) SetStatus(ctx context.Context, accountID, reverseProxyID string, status service.Status) error {
	return nil
}

func (m *mockReverseProxyManager) ReloadAllServicesForAccount(ctx context.Context, accountID string) error {
	return nil
}

func (m *mockReverseProxyManager) ReloadService(ctx context.Context, accountID, reverseProxyID string) error {
	return nil
}

func (m *mockReverseProxyManager) GetServiceByID(ctx context.Context, accountID, reverseProxyID string) (*service.Service, error) {
	return &service.Service{}, nil
}

func (m *mockReverseProxyManager) GetServiceIDByTargetID(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (m *mockReverseProxyManager) CreateServiceFromPeer(_ context.Context, _, _ string, _ *service.ExposeServiceRequest) (*service.ExposeServiceResponse, error) {
	return &service.ExposeServiceResponse{}, nil
}

func (m *mockReverseProxyManager) RenewServiceFromPeer(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockReverseProxyManager) StopServiceFromPeer(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockReverseProxyManager) StartExposeReaper(_ context.Context) {}

func (m *mockReverseProxyManager) GetServiceByDomain(_ context.Context, domain string) (*service.Service, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, services := range m.proxiesByAccount {
		for _, svc := range services {
			if svc.Domain == domain {
				return svc, nil
			}
		}
	}
	return nil, errors.New("service not found for domain: " + domain)
}

func (m *mockReverseProxyManager) GetClusters(_ context.Context, _, _ string) ([]proxy.Cluster, error) {
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

func (m *mockUsersManager) GetUserWithGroups(ctx context.Context, userID string) (*types.User, []*types.Group, error) {
	user, err := m.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	return user, nil, nil
}

// mockTunnelPeersManager implements only the two peers.Manager methods that
// ValidateTunnelPeer calls; the embedded interface satisfies the rest (and
// panics if any unexpected method is invoked).
type mockTunnelPeersManager struct {
	peers.Manager
	peer      *peer.Peer
	peerErr   error
	groups    []*types.Group
	groupsErr error
}

func (m *mockTunnelPeersManager) GetPeerByTunnelIP(_ context.Context, _ string, _ net.IP) (*peer.Peer, error) {
	return m.peer, m.peerErr
}

func (m *mockTunnelPeersManager) GetPeerWithGroups(_ context.Context, _, _ string) (*peer.Peer, []*types.Group, error) {
	return m.peer, m.groups, m.groupsErr
}

// mockTunnelIdpManager implements only GetUserDataByID; the embedded interface
// satisfies the rest of idp.Manager. hasData==false returns (nil, nil) to model
// an IdP that knows nothing about the user.
type mockTunnelIdpManager struct {
	idp.Manager
	email    string
	hasData  bool
	err      error
	gotCalls int
	gotMeta  []idp.AppMetadata
}

func (m *mockTunnelIdpManager) GetUserDataByID(_ context.Context, userID string, meta idp.AppMetadata) (*idp.UserData, error) {
	m.gotCalls++
	m.gotMeta = append(m.gotMeta, meta)
	if m.err != nil {
		return nil, m.err
	}
	if !m.hasData {
		// This might not be a thing any of the actual IDP implementations do,
		// i.e. return a nil value with no error, but it seems valuable to test
		// that behavior here.
		return nil, nil //nolint:nilnil
	}
	return &idp.UserData{ID: userID, Email: m.email}, nil
}

func TestValidateUserGroupAccess(t *testing.T) {
	tests := []struct {
		name             string
		domain           string
		userID           string
		proxiesByAccount map[string][]*service.Service
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
			proxiesByAccount: map[string][]*service.Service{
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
			proxiesByAccount: map[string][]*service.Service{},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr:    true,
			expectErrMsg: "service not found",
		},
		{
			name:   "proxy exists in different account - not accessible",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*service.Service{
				"account2": {{Domain: "app.example.com", AccountID: "account2"}},
			},
			users: map[string]*types.User{
				"user1": {Id: "user1", AccountID: "account1"},
			},
			expectErr:    true,
			expectErrMsg: "service not found",
		},
		{
			name:   "no bearer auth configured - same account allows access",
			domain: "app.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{Domain: "app.example.com", AccountID: "account1", Auth: service.AuthConfig{}}},
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
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: service.AuthConfig{
						BearerAuth: &service.BearerAuthConfig{Enabled: false},
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
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: service.AuthConfig{
						BearerAuth: &service.BearerAuthConfig{
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
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: service.AuthConfig{
						BearerAuth: &service.BearerAuthConfig{
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
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: service.AuthConfig{
						BearerAuth: &service.BearerAuthConfig{
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
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{
					Domain:    "app.example.com",
					AccountID: "account1",
					Auth: service.AuthConfig{
						BearerAuth: &service.BearerAuthConfig{
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
			expectErrMsg: "get account services",
		},
		{
			name:   "multiple proxies in account - finds correct one",
			domain: "app2.example.com",
			userID: "user1",
			proxiesByAccount: map[string][]*service.Service{
				"account1": {
					{Domain: "app1.example.com", AccountID: "account1"},
					{Domain: "app2.example.com", AccountID: "account1", Auth: service.AuthConfig{}},
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
				serviceManager: &mockReverseProxyManager{
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

// TestValidateTunnelPeerUserEmailEnrichment verifies the UserEmail/UserId
// resolution in ValidateTunnelPeer, including the IdP-enrichment fallback order
// (IdP email -> stored User.Email -> peer.Name).
func TestValidateTunnelPeerUserEmailEnrichment(t *testing.T) {
	const (
		domain    = "app.example.com"
		accountID = "account1"
		peerID    = "peer1"
		peerName  = "peer-display-name"
		userID    = "user1"
	)

	storedUser := map[string]*types.User{userID: {Id: userID, AccountID: accountID, Email: "stored@example.com"}}
	storedUserNoEmail := map[string]*types.User{userID: {Id: userID, AccountID: accountID, Email: ""}}

	tests := []struct {
		name         string
		peerUserID   string
		storedUsers  map[string]*types.User
		storedErr    error
		noIdP        bool
		idpEmail     string
		idpHasData   bool
		idpErr       error
		expectEmail  string
		expectUserID string
		expectIdPHit bool
	}{
		{
			name:         "idp email wins over stored email",
			peerUserID:   userID,
			storedUsers:  storedUser,
			idpEmail:     "idp@example.com",
			idpHasData:   true,
			expectEmail:  "idp@example.com",
			expectUserID: userID,
			expectIdPHit: true,
		},
		{
			name:         "stored email when idp returns empty email",
			peerUserID:   userID,
			storedUsers:  storedUser,
			idpEmail:     "",
			idpHasData:   true,
			expectEmail:  "stored@example.com",
			expectUserID: userID,
			expectIdPHit: true,
		},
		{
			name:         "stored email when idp has no data",
			peerUserID:   userID,
			storedUsers:  storedUser,
			idpHasData:   false,
			expectEmail:  "stored@example.com",
			expectUserID: userID,
			expectIdPHit: true,
		},
		{
			name:         "stored email when idp errors",
			peerUserID:   userID,
			storedUsers:  storedUser,
			idpErr:       errors.New("idp unreachable"),
			expectEmail:  "stored@example.com",
			expectUserID: userID,
			expectIdPHit: true,
		},
		{
			name:         "stored email when no idp manager",
			peerUserID:   userID,
			storedUsers:  storedUser,
			noIdP:        true,
			expectEmail:  "stored@example.com",
			expectUserID: userID,
		},
		{
			name:         "idp email when stored email is empty",
			peerUserID:   userID,
			storedUsers:  storedUserNoEmail,
			idpEmail:     "idp@example.com",
			idpHasData:   true,
			expectEmail:  "idp@example.com",
			expectUserID: userID,
			expectIdPHit: true,
		},
		{
			name:         "idp email when stored user missing keeps peer.UserID as principal",
			peerUserID:   userID,
			storedUsers:  map[string]*types.User{},
			idpEmail:     "idp@example.com",
			idpHasData:   true,
			expectEmail:  "idp@example.com",
			expectUserID: userID,
			expectIdPHit: true,
		},
		{
			name:         "unlinked peer uses peer name and never consults idp",
			peerUserID:   "",
			storedUsers:  storedUser,
			idpEmail:     "idp@example.com",
			idpHasData:   true,
			expectEmail:  peerName,
			expectUserID: peerID,
			expectIdPHit: false,
		},
		{
			name:         "linked peer with empty stored email and no idp falls back to peer name",
			peerUserID:   userID,
			storedUsers:  storedUserNoEmail,
			noIdP:        true,
			expectEmail:  peerName,
			expectUserID: userID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service.Service{Domain: domain, AccountID: accountID}
			server := &ProxyServiceServer{
				serviceManager: &mockReverseProxyManager{
					proxiesByAccount: map[string][]*service.Service{accountID: {svc}},
				},
				peersManager: &mockTunnelPeersManager{
					peer: &peer.Peer{ID: peerID, Name: peerName, UserID: tt.peerUserID},
				},
				usersManager: &mockUsersManager{users: tt.storedUsers, err: tt.storedErr},
			}

			var idpMock *mockTunnelIdpManager
			if !tt.noIdP {
				idpMock = &mockTunnelIdpManager{email: tt.idpEmail, hasData: tt.idpHasData, err: tt.idpErr}
				server.idpManager = idpMock
			}

			resp, err := server.ValidateTunnelPeer(context.Background(), &proto.ValidateTunnelPeerRequest{
				Domain:   domain,
				TunnelIp: "100.64.0.1",
			})

			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.GetValid(), "expected access granted")
			assert.Equal(t, tt.expectEmail, resp.GetUserEmail())
			assert.Equal(t, tt.expectUserID, resp.GetUserId())

			if idpMock != nil {
				if tt.expectIdPHit {
					assert.Equal(t, 1, idpMock.gotCalls, "expected IdP to be consulted")
					require.Len(t, idpMock.gotMeta, 1)
					assert.Equal(t, accountID, idpMock.gotMeta[0].WTAccountID)
				} else {
					assert.Equal(t, 0, idpMock.gotCalls, "expected IdP to not be consulted")
				}
			}
		})
	}
}

func TestGetAccountProxyByDomain(t *testing.T) {
	tests := []struct {
		name             string
		accountID        string
		domain           string
		proxiesByAccount map[string][]*service.Service
		err              error
		expectProxy      bool
		expectErr        bool
	}{
		{
			name:      "proxy found",
			accountID: "account1",
			domain:    "app.example.com",
			proxiesByAccount: map[string][]*service.Service{
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
			proxiesByAccount: map[string][]*service.Service{
				"account1": {{Domain: "app.example.com", AccountID: "account1"}},
			},
			expectProxy: false,
			expectErr:   true,
		},
		{
			name:             "empty proxy list for account",
			accountID:        "account1",
			domain:           "app.example.com",
			proxiesByAccount: map[string][]*service.Service{},
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
				serviceManager: &mockReverseProxyManager{
					proxiesByAccount: tt.proxiesByAccount,
					err:              tt.err,
				},
			}

			proxy, err := server.getAccountServiceByDomain(context.Background(), tt.accountID, tt.domain)

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

func TestCheckPeerGroupAccess(t *testing.T) {
	t.Run("private with empty AccessGroups denies", func(t *testing.T) {
		svc := &service.Service{Private: true, AccessGroups: nil}
		err := checkPeerGroupAccess(svc, []string{"grp-admins"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no access groups")
	})

	t.Run("private with peer in AccessGroups allows", func(t *testing.T) {
		svc := &service.Service{Private: true, AccessGroups: []string{"grp-admins", "grp-ops"}}
		assert.NoError(t, checkPeerGroupAccess(svc, []string{"grp-other", "grp-ops"}))
	})

	t.Run("private with peer outside AccessGroups denies", func(t *testing.T) {
		svc := &service.Service{Private: true, AccessGroups: []string{"grp-admins"}}
		assert.Error(t, checkPeerGroupAccess(svc, []string{"grp-other"}))
	})

	t.Run("bearer enabled with empty DistributionGroups allows", func(t *testing.T) {
		svc := &service.Service{
			Auth: service.AuthConfig{BearerAuth: &service.BearerAuthConfig{Enabled: true}},
		}
		assert.NoError(t, checkPeerGroupAccess(svc, []string{"grp-anyone"}))
	})

	t.Run("bearer enabled gates on DistributionGroups", func(t *testing.T) {
		svc := &service.Service{
			Auth: service.AuthConfig{
				BearerAuth: &service.BearerAuthConfig{
					Enabled:            true,
					DistributionGroups: []string{"grp-allowed"},
				},
			},
		}
		assert.NoError(t, checkPeerGroupAccess(svc, []string{"grp-allowed"}))
		assert.Error(t, checkPeerGroupAccess(svc, []string{"grp-other"}))
	})

	t.Run("non-private non-bearer is open", func(t *testing.T) {
		assert.NoError(t, checkPeerGroupAccess(&service.Service{}, nil))
	})
}
