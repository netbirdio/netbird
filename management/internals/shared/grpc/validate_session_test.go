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

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
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

	proxyManager := &testValidateSessionProxyManager{store: testStore}
	usersManager := &testValidateSessionUsersManager{store: testStore}

	proxyService := NewProxyServiceServer(nil, NewOneTimeTokenStore(time.Minute), ProxyOIDCConfig{}, nil, usersManager)
	proxyService.SetProxyManager(proxyManager)

	createTestProxies(t, ctx, testStore)

	return &validateSessionTestSetup{
		proxyService: proxyService,
		store:        testStore,
		cleanup:      storeCleanup,
	}
}

func createTestProxies(t *testing.T, ctx context.Context, testStore store.Store) {
	t.Helper()

	pubKey, privKey := generateSessionKeyPair(t)

	testProxy := &reverseproxy.Service{
		ID:                "testProxyId",
		AccountID:         "testAccountId",
		Name:              "Test Proxy",
		Domain:            "test-proxy.example.com",
		Enabled:           true,
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
		Auth: reverseproxy.AuthConfig{
			BearerAuth: &reverseproxy.BearerAuthConfig{
				Enabled: true,
			},
		},
	}
	require.NoError(t, testStore.CreateService(ctx, testProxy))

	restrictedProxy := &reverseproxy.Service{
		ID:                "restrictedProxyId",
		AccountID:         "testAccountId",
		Name:              "Restricted Proxy",
		Domain:            "restricted-proxy.example.com",
		Enabled:           true,
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
		Auth: reverseproxy.AuthConfig{
			BearerAuth: &reverseproxy.BearerAuthConfig{
				Enabled:            true,
				DistributionGroups: []string{"allowedGroupId"},
			},
		},
	}
	require.NoError(t, testStore.CreateService(ctx, restrictedProxy))
}

func generateSessionKeyPair(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv)
}

func createSessionToken(t *testing.T, privKeyB64, userID, domain string) string {
	t.Helper()
	token, err := sessionkey.SignToken(privKeyB64, userID, domain, auth.MethodOIDC, time.Hour)
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
	assert.Equal(t, "proxy_not_found", resp.DeniedReason)
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

type testValidateSessionProxyManager struct {
	store store.Store
}

func (m *testValidateSessionProxyManager) GetAllServices(_ context.Context, _, _ string) ([]*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) GetService(_ context.Context, _, _, _ string) (*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) CreateService(_ context.Context, _, _ string, _ *reverseproxy.Service) (*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) UpdateService(_ context.Context, _, _ string, _ *reverseproxy.Service) (*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testValidateSessionProxyManager) DeleteService(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) SetCertificateIssuedAt(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) SetStatus(_ context.Context, _, _ string, _ reverseproxy.ProxyStatus) error {
	return nil
}

func (m *testValidateSessionProxyManager) ReloadAllServicesForAccount(_ context.Context, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) ReloadService(_ context.Context, _, _ string) error {
	return nil
}

func (m *testValidateSessionProxyManager) GetGlobalServices(ctx context.Context) ([]*reverseproxy.Service, error) {
	return m.store.GetServices(ctx, store.LockingStrengthNone)
}

func (m *testValidateSessionProxyManager) GetServiceByID(ctx context.Context, accountID, proxyID string) (*reverseproxy.Service, error) {
	return m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, proxyID)
}

func (m *testValidateSessionProxyManager) GetAccountServices(ctx context.Context, accountID string) ([]*reverseproxy.Service, error) {
	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
}

func (m *testValidateSessionProxyManager) GetServiceIDByTargetID(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

type testValidateSessionUsersManager struct {
	store store.Store
}

func (m *testValidateSessionUsersManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	return m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
}
