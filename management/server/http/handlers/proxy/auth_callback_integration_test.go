//go:build integration

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakeOIDCServer creates a minimal OIDC provider for testing.
type fakeOIDCServer struct {
	server       *httptest.Server
	issuer       string
	signingKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	keyID        string
	tokenSubject string
	tokenExpiry  time.Duration
	failExchange bool
}

func newFakeOIDCServer() *fakeOIDCServer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeOIDCServer{
		signingKey:  priv,
		publicKey:   pub,
		keyID:       "test-key-1",
		tokenExpiry: time.Hour,
	}
	f.server = httptest.NewServer(f)
	f.issuer = f.server.URL
	return f
}

func (f *fakeOIDCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		f.handleDiscovery(w, r)
	case "/token":
		f.handleToken(w, r)
	case "/keys":
		f.handleJWKS(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                 f.issuer,
		"authorization_endpoint": f.issuer + "/auth",
		"token_endpoint":         f.issuer + "/token",
		"jwks_uri":               f.issuer + "/keys",
		"response_types_supported": []string{
			"code",
			"id_token",
			"token id_token",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (f *fakeOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if f.failExchange {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	idToken := f.createIDToken()

	response := map[string]interface{}{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      idToken,
		"refresh_token": "test-refresh-token",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (f *fakeOIDCServer) createIDToken() string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": f.issuer,
		"sub": f.tokenSubject,
		"aud": "test-client-id",
		"exp": now.Add(f.tokenExpiry).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = f.keyID
	signed, _ := token.SignedString(f.signingKey)
	return signed
}

func (f *fakeOIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": f.keyID,
				"x":   base64.RawURLEncoding.EncodeToString(f.publicKey),
				"use": "sig",
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (f *fakeOIDCServer) Close() {
	f.server.Close()
}

// testSetup contains all test dependencies.
type testSetup struct {
	store        store.Store
	oidcServer   *fakeOIDCServer
	proxyService *nbgrpc.ProxyServiceServer
	handler      *AuthCallbackHandler
	router       *mux.Router
	cleanup      func()
}

// testAccessLogManager is a minimal mock for accesslogs.Manager.
type testAccessLogManager struct{}

func (m *testAccessLogManager) SaveAccessLog(_ context.Context, _ *accesslogs.AccessLogEntry) error {
	return nil
}

func (m *testAccessLogManager) GetAllAccessLogs(_ context.Context, _, _ string, _ *accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	return nil, 0, nil
}

func setupAuthCallbackTest(t *testing.T) *testSetup {
	t.Helper()

	ctx := context.Background()

	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)

	createTestAccountsAndUsers(t, ctx, testStore)
	createTestReverseProxies(t, ctx, testStore)

	oidcServer := newFakeOIDCServer()

	tokenStore := nbgrpc.NewOneTimeTokenStore(time.Minute)

	usersManager := users.NewManager(testStore)

	oidcConfig := nbgrpc.ProxyOIDCConfig{
		Issuer:      oidcServer.issuer,
		ClientID:    "test-client-id",
		Scopes:      []string{"openid", "profile", "email"},
		CallbackURL: "https://management.example.com/reverse-proxy/callback",
		HMACKey:     []byte("test-hmac-key-for-state-signing"),
	}

	proxyService := nbgrpc.NewProxyServiceServer(
		&testAccessLogManager{},
		tokenStore,
		oidcConfig,
		nil,
		usersManager,
	)

	proxyService.SetProxyManager(&testServiceManager{store: testStore})

	handler := NewAuthCallbackHandler(proxyService, nil)

	router := mux.NewRouter()
	handler.RegisterEndpoints(router)

	return &testSetup{
		store:        testStore,
		oidcServer:   oidcServer,
		proxyService: proxyService,
		handler:      handler,
		router:       router,
		cleanup: func() {
			cleanup()
			oidcServer.Close()
		},
	}
}

func createTestReverseProxies(t *testing.T, ctx context.Context, testStore store.Store) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey := base64.StdEncoding.EncodeToString(pub)
	privKey := base64.StdEncoding.EncodeToString(priv)

	testProxy := &reverseproxy.Service{
		ID:        "testProxyId",
		AccountID: "testAccountId",
		Name:      "Test Proxy",
		Domain:    "test-proxy.example.com",
		Targets: []*reverseproxy.Target{{
			Path:       strPtr("/"),
			Host:       "localhost",
			Port:       8080,
			Protocol:   "http",
			TargetId:   "peer1",
			TargetType: "peer",
			Enabled:    true,
		}},
		Enabled: true,
		Auth: reverseproxy.AuthConfig{
			BearerAuth: &reverseproxy.BearerAuthConfig{
				Enabled:            true,
				DistributionGroups: []string{"allowedGroupId"},
			},
		},
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
	}
	require.NoError(t, testStore.CreateService(ctx, testProxy))

	restrictedProxy := &reverseproxy.Service{
		ID:        "restrictedProxyId",
		AccountID: "testAccountId",
		Name:      "Restricted Proxy",
		Domain:    "restricted-proxy.example.com",
		Targets: []*reverseproxy.Target{{
			Path:       strPtr("/"),
			Host:       "localhost",
			Port:       8080,
			Protocol:   "http",
			TargetId:   "peer1",
			TargetType: "peer",
			Enabled:    true,
		}},
		Enabled: true,
		Auth: reverseproxy.AuthConfig{
			BearerAuth: &reverseproxy.BearerAuthConfig{
				Enabled:            true,
				DistributionGroups: []string{"restrictedGroupId"},
			},
		},
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
	}
	require.NoError(t, testStore.CreateService(ctx, restrictedProxy))

	noAuthProxy := &reverseproxy.Service{
		ID:        "noAuthProxyId",
		AccountID: "testAccountId",
		Name:      "No Auth Proxy",
		Domain:    "no-auth-proxy.example.com",
		Targets: []*reverseproxy.Target{{
			Path:       strPtr("/"),
			Host:       "localhost",
			Port:       8080,
			Protocol:   "http",
			TargetId:   "peer1",
			TargetType: "peer",
			Enabled:    true,
		}},
		Enabled: true,
		Auth: reverseproxy.AuthConfig{
			BearerAuth: &reverseproxy.BearerAuthConfig{
				Enabled: false,
			},
		},
		SessionPrivateKey: privKey,
		SessionPublicKey:  pubKey,
	}
	require.NoError(t, testStore.CreateService(ctx, noAuthProxy))
}

func strPtr(s string) *string {
	return &s
}

func createTestAccountsAndUsers(t *testing.T, ctx context.Context, testStore store.Store) {
	t.Helper()

	testAccount := &types.Account{
		Id:                     "testAccountId",
		Domain:                 "test.com",
		DomainCategory:         "private",
		IsDomainPrimaryAccount: true,
		CreatedAt:              time.Now(),
	}
	require.NoError(t, testStore.SaveAccount(ctx, testAccount))

	allowedGroup := &types.Group{
		ID:        "allowedGroupId",
		AccountID: "testAccountId",
		Name:      "Allowed Group",
		Issued:    "api",
	}
	require.NoError(t, testStore.CreateGroup(ctx, allowedGroup))

	allowedUser := &types.User{
		Id:         "allowedUserId",
		AccountID:  "testAccountId",
		Role:       types.UserRoleUser,
		AutoGroups: []string{"allowedGroupId"},
		CreatedAt:  time.Now(),
		Issued:     "api",
	}
	require.NoError(t, testStore.SaveUser(ctx, allowedUser))
}

// testServiceManager is a minimal implementation for testing.
type testServiceManager struct {
	store store.Store
}

func (m *testServiceManager) GetAllServices(_ context.Context, _, _ string) ([]*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testServiceManager) GetService(_ context.Context, _, _, _ string) (*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testServiceManager) CreateService(_ context.Context, _, _ string, _ *reverseproxy.Service) (*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testServiceManager) UpdateService(_ context.Context, _, _ string, _ *reverseproxy.Service) (*reverseproxy.Service, error) {
	return nil, nil
}

func (m *testServiceManager) DeleteService(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *testServiceManager) SetCertificateIssuedAt(_ context.Context, _, _ string) error {
	return nil
}

func (m *testServiceManager) SetStatus(_ context.Context, _, _ string, _ reverseproxy.ProxyStatus) error {
	return nil
}

func (m *testServiceManager) ReloadAllServicesForAccount(_ context.Context, _ string) error {
	return nil
}

func (m *testServiceManager) ReloadService(_ context.Context, _, _ string) error {
	return nil
}

func (m *testServiceManager) GetGlobalServices(ctx context.Context) ([]*reverseproxy.Service, error) {
	return m.store.GetServices(ctx, store.LockingStrengthNone)
}

func (m *testServiceManager) GetServiceByID(ctx context.Context, accountID, proxyID string) (*reverseproxy.Service, error) {
	return m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, proxyID)
}

func (m *testServiceManager) GetAccountServices(ctx context.Context, accountID string) ([]*reverseproxy.Service, error) {
	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
}

func (m *testServiceManager) GetServiceIDByTargetID(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func createTestState(t *testing.T, ps *nbgrpc.ProxyServiceServer, redirectURL string) string {
	t.Helper()

	resp, err := ps.GetOIDCURL(context.Background(), &proto.GetOIDCURLRequest{
		RedirectUrl: redirectURL,
		AccountId:   "testAccountId",
	})
	require.NoError(t, err)

	parsedURL, err := url.Parse(resp.Url)
	require.NoError(t, err)

	return parsedURL.Query().Get("state")
}

func TestAuthCallback_UserAllowedToLogin(t *testing.T) {
	setup := setupAuthCallbackTest(t)
	defer setup.cleanup()

	setup.oidcServer.tokenSubject = "allowedUserId"

	state := createTestState(t, setup.proxyService, "https://test-proxy.example.com/dashboard")

	req := httptest.NewRequest(http.MethodGet, "/reverse-proxy/callback?code=test-auth-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()

	setup.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)

	location := rec.Header().Get("Location")
	require.NotEmpty(t, location)

	parsedLocation, err := url.Parse(location)
	require.NoError(t, err)

	require.Equal(t, "test-proxy.example.com", parsedLocation.Host)
	require.NotEmpty(t, parsedLocation.Query().Get("session_token"), "Should include session token")
	require.Empty(t, parsedLocation.Query().Get("error"), "Should not have error parameter")
}

func TestAuthCallback_ProxyNotFound(t *testing.T) {
	setup := setupAuthCallbackTest(t)
	defer setup.cleanup()

	setup.oidcServer.tokenSubject = "allowedUserId"

	state := createTestState(t, setup.proxyService, "https://test-proxy.example.com/")

	require.NoError(t, setup.store.DeleteService(context.Background(), "testAccountId", "testProxyId"))

	req := httptest.NewRequest(http.MethodGet, "/reverse-proxy/callback?code=test-auth-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()

	setup.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)

	location := rec.Header().Get("Location")
	parsedLocation, err := url.Parse(location)
	require.NoError(t, err)

	require.Equal(t, "access_denied", parsedLocation.Query().Get("error"))
}

func TestAuthCallback_InvalidToken(t *testing.T) {
	setup := setupAuthCallbackTest(t)
	defer setup.cleanup()

	setup.oidcServer.failExchange = true

	state := createTestState(t, setup.proxyService, "https://test-proxy.example.com/")

	req := httptest.NewRequest(http.MethodGet, "/reverse-proxy/callback?code=invalid-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()

	setup.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "Failed to exchange code")
}

func TestAuthCallback_ExpiredToken(t *testing.T) {
	setup := setupAuthCallbackTest(t)
	defer setup.cleanup()

	setup.oidcServer.tokenSubject = "allowedUserId"
	setup.oidcServer.tokenExpiry = -time.Hour

	state := createTestState(t, setup.proxyService, "https://test-proxy.example.com/")

	req := httptest.NewRequest(http.MethodGet, "/reverse-proxy/callback?code=test-auth-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()

	setup.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "Failed to validate token")
}

func TestAuthCallback_InvalidState(t *testing.T) {
	setup := setupAuthCallbackTest(t)
	defer setup.cleanup()

	req := httptest.NewRequest(http.MethodGet, "/reverse-proxy/callback?code=test-auth-code&state=invalid-state", nil)
	rec := httptest.NewRecorder()

	setup.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "Invalid state")
}

func TestAuthCallback_MissingState(t *testing.T) {
	setup := setupAuthCallbackTest(t)
	defer setup.cleanup()

	req := httptest.NewRequest(http.MethodGet, "/reverse-proxy/callback?code=test-auth-code", nil)
	rec := httptest.NewRecorder()

	setup.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}
