//go:build integration

package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type validateSessionTestSetup struct {
	proxyService *ProxyServiceServer
	store        store.Store
	cleanup      func()
}

func setupValidateSessionTest(t *testing.T) *validateSessionTestSetup {
	t.Helper()

	ctx := context.Background()
	testStore, storeCleanup, err := store.NewTestStoreFromSQL(ctx, "../../../server/testdata/auth_callback.sql", t.TempDir())
	require.NoError(t, err)

	serviceManager := &testValidateSessionServiceManager{store: testStore}
	usersManager := &testValidateSessionUsersManager{store: testStore}
	proxyManager := &testValidateSessionProxyManager{}

	tokenStore := NewOneTimeTokenStore(ctx, testCacheStore(t))
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	proxyService := NewProxyServiceServer(nil, tokenStore, pkceStore, ProxyOIDCConfig{}, nil, usersManager, nil, proxyManager, nil)
	proxyService.SetServiceManager(serviceManager)

	createTestProxies(t, ctx, testStore)
	createStatusTestUsers(t, ctx, testStore)

	return &validateSessionTestSetup{
		proxyService: proxyService,
		store:        testStore,
		cleanup:      storeCleanup,
	}
}

func createTestProxies(t *testing.T, ctx context.Context, testStore store.Store) {
	t.Helper()

	pubKey, privKey := generateSessionKeyPair(t)

	testProxy := &service.Service{
		ID:                "testProxyId",
		AccountID:         "testAccountId",
		Name:              "Test Proxy",
		Domain:            "test-proxy.example.com",
		Enabled:           true,
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
		Auth: service.AuthConfig{
			BearerAuth: &service.BearerAuthConfig{
				Enabled: true,
			},
		},
	}
	require.NoError(t, testStore.CreateService(ctx, testProxy))

	restrictedProxy := &service.Service{
		ID:                "restrictedProxyId",
		AccountID:         "testAccountId",
		Name:              "Restricted Proxy",
		Domain:            "restricted-proxy.example.com",
		Enabled:           true,
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
		Auth: service.AuthConfig{
			BearerAuth: &service.BearerAuthConfig{
				Enabled:            true,
				DistributionGroups: []string{"allowedGroupId"},
			},
		},
	}
	require.NoError(t, testStore.CreateService(ctx, restrictedProxy))

	// Distributed to the account's "All" group, the configuration that hands a
	// service to every user in the account.
	allUsersProxy := &service.Service{
		ID:                "allUsersProxyId",
		AccountID:         "testAccountId",
		Name:              "All Users Proxy",
		Domain:            "all-users-proxy.example.com",
		Enabled:           true,
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
		Auth: service.AuthConfig{
			BearerAuth: &service.BearerAuthConfig{
				Enabled:            true,
				DistributionGroups: []string{allUsersGroupID},
			},
		},
	}
	require.NoError(t, testStore.CreateService(ctx, allUsersProxy))
}

const (
	allUsersGroupID   = "allUsersGroupId"
	pendingUserID     = "pendingUserId"
	blockedUserID     = "blockedUserId"
	pendingAllUsersID = "pendingAllUsersUserId"
)

// createStatusTestUsers adds the users whose account status must keep them out
// of a proxy session. A user awaiting approval is persisted as both blocked and
// pending approval, the way the approval flow stores one.
func createStatusTestUsers(t *testing.T, ctx context.Context, testStore store.Store) {
	t.Helper()

	require.NoError(t, testStore.CreateGroup(ctx, &types.Group{
		ID:        allUsersGroupID,
		AccountID: "testAccountId",
		Name:      "All",
		Issued:    types.GroupIssuedAPI,
	}))

	users := []*types.User{
		{
			Id:              pendingUserID,
			AccountID:       "testAccountId",
			Role:            types.UserRoleUser,
			AutoGroups:      []string{"allowedGroupId"},
			Blocked:         true,
			PendingApproval: true,
			Issued:          "api",
			CreatedAt:       time.Now(),
		},
		{
			Id:              pendingAllUsersID,
			AccountID:       "testAccountId",
			Role:            types.UserRoleUser,
			AutoGroups:      []string{allUsersGroupID},
			Blocked:         true,
			PendingApproval: true,
			Issued:          "api",
			CreatedAt:       time.Now(),
		},
		{
			Id:              blockedUserID,
			AccountID:       "testAccountId",
			Role:            types.UserRoleUser,
			AutoGroups:      []string{"allowedGroupId"},
			Blocked:         true,
			PendingApproval: false,
			Issued:          "api",
			CreatedAt:       time.Now(),
		},
	}
	for _, user := range users {
		require.NoError(t, testStore.SaveUser(ctx, user))
	}
}

func generateSessionKeyPair(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv)
}

func createSessionToken(t *testing.T, privKeyB64, userID, domain string) string {
	t.Helper()
	token, err := sessionkey.SignToken(privKeyB64, userID, "", domain, auth.MethodOIDC, nil, nil, time.Hour)
	require.NoError(t, err)
	return token
}

func TestValidateSession_UserAllowed(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "testProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, "allowedUserId", "test-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "test-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.True(t, resp.Valid, "User should be allowed access")
	assert.Equal(t, "allowedUserId", resp.UserId)
	assert.Empty(t, resp.DeniedReason)
	assert.Equal(t, []string{"allowedGroupId"}, resp.GetPeerGroupIds(), "PeerGroupIds must mirror the resolved user's group memberships")
}

func TestValidateSession_UserNotInAllowedGroup(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "restrictedProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, "nonGroupUserId", "restricted-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "restricted-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "User not in group should be denied")
	assert.Equal(t, "not_in_group", resp.DeniedReason)
	assert.Equal(t, "nonGroupUserId", resp.UserId)
	assert.Empty(t, resp.GetPeerGroupIds(), "PeerGroupIds must mirror the resolved user's actual (empty) memberships on denial")
}

// TestValidateSession_PendingApprovalUserDenied covers a user who is a member of
// the service's distribution group but is still waiting for an administrator to
// approve the account. Group membership alone must not open the service.
func TestValidateSession_PendingApprovalUserDenied(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "restrictedProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, pendingUserID, "restricted-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "restricted-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "User pending approval should be denied")
	assert.Equal(t, deniedReasonPendingApproval, resp.DeniedReason, "Denied reason should name the pending approval state")
	assert.Equal(t, pendingUserID, resp.UserId, "Denial should identify the user it applies to")
	assert.Equal(t, []string{"allowedGroupId"}, resp.GetPeerGroupIds(), "PeerGroupIds must mirror the resolved user's group memberships on denial")
	assert.Equal(t, []string{"Allowed Group"}, resp.GetPeerGroupNames(), "PeerGroupNames must pair with PeerGroupIds on denial")
}

// TestValidateSession_PendingApprovalUserInAllUsersGroupDenied covers the same
// user against a service distributed to the account's "All" group, where every
// user of the account is a member by default.
func TestValidateSession_PendingApprovalUserInAllUsersGroupDenied(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "allUsersProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, pendingAllUsersID, "all-users-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "all-users-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "User pending approval should be denied even in the All Users group")
	assert.Equal(t, deniedReasonPendingApproval, resp.DeniedReason, "Denied reason should name the pending approval state")
	assert.Equal(t, pendingAllUsersID, resp.UserId, "Denial should identify the user it applies to")
	assert.Equal(t, []string{allUsersGroupID}, resp.GetPeerGroupIds(), "PeerGroupIds must mirror the resolved user's group memberships on denial")
}

// TestValidateSession_BlockedUserDenied covers a user blocked after having been
// approved, so PendingApproval is false and only the blocked flag is set.
func TestValidateSession_BlockedUserDenied(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "restrictedProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, blockedUserID, "restricted-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "restricted-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "Blocked user should be denied")
	assert.Equal(t, deniedReasonUserBlocked, resp.DeniedReason, "Denied reason should name the blocked state")
	assert.Equal(t, blockedUserID, resp.UserId, "Denial should identify the user it applies to")
}

// TestValidateSession_UserAllowedAfterApproval walks the same session token
// through the approval transition: denied while pending, allowed once an
// administrator clears both flags.
func TestValidateSession_UserAllowedAfterApproval(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	ctx := context.Background()

	proxy, err := setup.store.GetServiceByID(ctx, store.LockingStrengthNone, "testAccountId", "restrictedProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, pendingUserID, "restricted-proxy.example.com")
	req := &proto.ValidateSessionRequest{
		Domain:       "restricted-proxy.example.com",
		SessionToken: token,
	}

	resp, err := setup.proxyService.ValidateSession(ctx, req)
	require.NoError(t, err)
	require.False(t, resp.Valid, "User pending approval should be denied before approval")
	assert.Equal(t, deniedReasonPendingApproval, resp.DeniedReason, "Denied reason should name the pending approval state")

	user, err := setup.store.GetUserByUserID(ctx, store.LockingStrengthNone, pendingUserID)
	require.NoError(t, err)
	user.PendingApproval = false
	user.Blocked = false
	require.NoError(t, setup.store.SaveUser(ctx, user))

	resp, err = setup.proxyService.ValidateSession(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Valid, "Approved user should be allowed access")
	assert.Empty(t, resp.DeniedReason)
	assert.Equal(t, pendingUserID, resp.UserId, "Approved user should be identified in the response")
	assert.Equal(t, []string{"allowedGroupId"}, resp.GetPeerGroupIds(), "PeerGroupIds must mirror the approved user's group memberships")
}

func TestValidateSession_UserInDifferentAccount(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "testProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, "otherAccountUserId", "test-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "test-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "User in different account should be denied")
	assert.Equal(t, "account_mismatch", resp.DeniedReason)
}

func TestValidateSession_UserNotFound(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "testProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, "nonExistentUserId", "test-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "test-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "Non-existent user should be denied")
	assert.Equal(t, "user_not_found", resp.DeniedReason)
}

func TestValidateSession_ProxyNotFound(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	proxy, err := setup.store.GetServiceByID(context.Background(), store.LockingStrengthNone, "testAccountId", "testProxyId")
	require.NoError(t, err)

	token := createSessionToken(t, proxy.SessionPrivateKey, "allowedUserId", "unknown-proxy.example.com")

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "unknown-proxy.example.com",
		SessionToken: token,
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "Unknown proxy should be denied")
	assert.Equal(t, "service_not_found", resp.DeniedReason)
}

func TestValidateSession_InvalidToken(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain:       "test-proxy.example.com",
		SessionToken: "invalid-token",
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid, "Invalid token should be denied")
	assert.Equal(t, "invalid_token", resp.DeniedReason)
}

func TestValidateSession_MissingDomain(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		SessionToken: "some-token",
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.Contains(t, resp.DeniedReason, "missing")
}

func TestValidateSession_MissingToken(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	resp, err := setup.proxyService.ValidateSession(context.Background(), &proto.ValidateSessionRequest{
		Domain: "test-proxy.example.com",
	})

	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.Contains(t, resp.DeniedReason, "missing")
}

// TestGenerateSessionToken_UserNotInAllowedGroupGetsNoToken is the regression
// guard for the group-authorisation bypass: the callback used to hand a signed
// token to a user the service denies, and the proxy honoured that token as soon
// as the user moved it into the nb_session cookie themselves. Authorisation has
// to run before the token is signed.
func TestGenerateSessionToken_UserNotInAllowedGroupGetsNoToken(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	token, err := setup.proxyService.GenerateSessionToken(context.Background(), "restricted-proxy.example.com", "nonGroupUserId", auth.MethodOIDC)

	require.Error(t, err, "a user outside the distribution groups must not receive a token")
	assert.ErrorIs(t, err, ErrUserNotInGroup, "the callback maps this sentinel onto the access denied page")
	assert.Empty(t, token, "no token may reach the browser")
}

func TestGenerateSessionToken_UserInAllowedGroupGetsTokenWithGroups(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	ctx := context.Background()
	svc, err := setup.store.GetServiceByID(ctx, store.LockingStrengthNone, "testAccountId", "restrictedProxyId")
	require.NoError(t, err)

	token, err := setup.proxyService.GenerateSessionToken(ctx, "restricted-proxy.example.com", "allowedUserId", auth.MethodOIDC)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	pubKey, err := base64.StdEncoding.DecodeString(svc.SessionPublicKey)
	require.NoError(t, err)

	userID, _, method, groups, _, err := auth.ValidateSessionJWT(token, "restricted-proxy.example.com", pubKey)
	require.NoError(t, err)
	assert.Equal(t, "allowedUserId", userID)
	assert.Equal(t, auth.MethodOIDC.String(), method)
	assert.Equal(t, []string{"allowedGroupId"}, groups, "the proxy gates the cookie on this claim, so it must carry the matched group")
}

// TestGenerateSessionToken_UnrestrictedServiceAllowsAnyAccountUser keeps the new
// gate scoped: a service without distribution groups is open to every user of
// its account, as before.
func TestGenerateSessionToken_UnrestrictedServiceAllowsAnyAccountUser(t *testing.T) {
	setup := setupValidateSessionTest(t)
	defer setup.cleanup()

	token, err := setup.proxyService.GenerateSessionToken(context.Background(), "test-proxy.example.com", "nonGroupUserId", auth.MethodOIDC)

	require.NoError(t, err, "an unrestricted service must keep working for any user of the account")
	assert.NotEmpty(t, token)
}

type testValidateSessionServiceManager struct {
	store store.Store
}

func (m *testValidateSessionServiceManager) GetAllServices(_ context.Context, _, _ string) ([]*service.Service, error) {
	return nil, nil
}

func (m *testValidateSessionServiceManager) GetService(_ context.Context, _, _, _ string) (*service.Service, error) {
	return nil, nil
}

func (m *testValidateSessionServiceManager) CreateService(_ context.Context, _, _ string, _ *service.Service) (*service.Service, error) {
	return nil, nil
}

func (m *testValidateSessionServiceManager) UpdateService(_ context.Context, _, _ string, _ *service.Service) (*service.Service, error) {
	return nil, nil
}

func (m *testValidateSessionServiceManager) DeleteService(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) DeleteAllServices(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) SetCertificateIssuedAt(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) SetStatus(_ context.Context, _, _ string, _ service.Status) error {
	return nil
}

func (m *testValidateSessionServiceManager) ReloadAllServicesForAccount(_ context.Context, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) ReloadService(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) GetGlobalServices(ctx context.Context) ([]*service.Service, error) {
	return m.store.GetServices(ctx, store.LockingStrengthNone)
}

func (m *testValidateSessionServiceManager) GetServiceByID(ctx context.Context, accountID, proxyID string) (*service.Service, error) {
	return m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, proxyID)
}

func (m *testValidateSessionServiceManager) GetAccountServices(ctx context.Context, accountID string) ([]*service.Service, error) {
	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
}

func (m *testValidateSessionServiceManager) GetServiceIDByTargetID(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (m *testValidateSessionServiceManager) CreateServiceFromPeer(_ context.Context, _, _ string, _ *service.ExposeServiceRequest) (*service.ExposeServiceResponse, error) {
	return nil, nil
}

func (m *testValidateSessionServiceManager) RenewServiceFromPeer(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) StopServiceFromPeer(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *testValidateSessionServiceManager) StartExposeReaper(_ context.Context) {}

func (m *testValidateSessionServiceManager) GetServiceByDomain(ctx context.Context, domain string) (*service.Service, error) {
	return m.store.GetServiceByDomain(ctx, domain)
}

func (m *testValidateSessionServiceManager) GetClusters(_ context.Context, _, _ string) ([]proxy.Cluster, error) {
	return nil, nil
}

func (m *testValidateSessionServiceManager) DeleteAccountCluster(_ context.Context, _, _, _ string) error {
	return nil
}

type testValidateSessionProxyManager struct{}

func (m *testValidateSessionProxyManager) Connect(_ context.Context, _, _, _, _ string, _ *string, _ *proxy.Capabilities) (*proxy.Proxy, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) Disconnect(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) Heartbeat(_ context.Context, _ *proxy.Proxy) error {
	return nil
}

func (m *testValidateSessionProxyManager) DeleteAccountCluster(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) GetActiveClusterAddresses(_ context.Context) ([]string, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) GetActiveClusterAddressesForAccount(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) GetActiveClusters(_ context.Context) ([]proxy.Cluster, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) CleanupStale(_ context.Context, _ time.Duration) error {
	return nil
}

func (m *testValidateSessionProxyManager) GetAccountProxy(_ context.Context, _ string) (*proxy.Proxy, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) CountAccountProxies(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (m *testValidateSessionProxyManager) IsClusterAddressAvailable(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

func (m *testValidateSessionProxyManager) DeleteProxy(_ context.Context, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) ClusterSupportsCustomPorts(_ context.Context, _ string) *bool {
	return nil
}

func (m *testValidateSessionProxyManager) ClusterRequireSubdomain(_ context.Context, _ string) *bool {
	return nil
}

func (m *testValidateSessionProxyManager) ClusterSupportsCrowdSec(_ context.Context, _ string) *bool {
	return nil
}

func (m *testValidateSessionProxyManager) ClusterSupportsPrivate(_ context.Context, _ string) *bool {
	return nil
}

type testValidateSessionUsersManager struct {
	store store.Store
}

func (m *testValidateSessionUsersManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	return m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
}

func (m *testValidateSessionUsersManager) GetUserWithGroups(ctx context.Context, userID string) (*types.User, []*types.Group, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(user.AutoGroups) == 0 {
		return user, nil, nil
	}
	groupsMap, err := m.store.GetGroupsByIDs(ctx, store.LockingStrengthNone, user.AccountID, user.AutoGroups)
	if err != nil {
		return nil, nil, err
	}
	groups := make([]*types.Group, 0, len(user.AutoGroups))
	for _, id := range user.AutoGroups {
		if g, ok := groupsMap[id]; ok && g != nil {
			groups = append(groups, g)
		}
	}
	return user, groups, nil
}
