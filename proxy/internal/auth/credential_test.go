package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	servicemanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	mgmttypes "github.com/netbirdio/netbird/management/server/types"
	proxyauth "github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// localCredentialClient replaces the transport while keeping the real service
// store, credential verification, and session signing.
type localCredentialClient struct {
	server *nbgrpc.ProxyServiceServer
}

func (c localCredentialClient) Authenticate(ctx context.Context, req *proto.AuthenticateRequest, _ ...grpc.CallOption) (*proto.AuthenticateResponse, error) {
	return c.server.Authenticate(ctx, req)
}

func credentialHandler(t *testing.T, field string) (*Middleware, http.Handler) {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewStore(ctx, mgmttypes.SqliteStoreEngine, t.TempDir(), nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close(ctx)) })
	require.NoError(t, s.SaveAccount(ctx, &mgmttypes.Account{Id: "account"}))
	keys := generateTestKeyPair(t)
	svc := &service.Service{
		ID: "service", AccountID: "account", Name: "test", Domain: "example.com",
		Enabled: true, SessionPrivateKey: keys.PrivateKey, SessionPublicKey: keys.PublicKey,
		Auth: service.AuthConfig{
			PinAuth:      &service.PINAuthConfig{Enabled: true, Pin: "842716"},
			PasswordAuth: &service.PasswordAuthConfig{Enabled: true, Password: "842716"},
		},
	}
	require.NoError(t, svc.Auth.HashSecrets())
	require.NoError(t, s.CreateService(ctx, svc))
	server := nbgrpc.NewProxyServiceServer(nil, nil, nil, nbgrpc.ProxyOIDCConfig{}, nil, nil, nil, nil, nil)
	t.Cleanup(server.Close)
	server.SetServiceManager(servicemanager.NewManager(s, nil, nil, nil, nil, nil))
	client := localCredentialClient{server: server}
	var scheme Scheme = NewPin(client, "service", "account")
	if field == "password" {
		scheme = NewPassword(client, "service", "account")
	}
	mw := NewMiddleware(nil, nil, nil)
	require.NoError(t, mw.AddDomain("example.com", DomainSettings{Schemes: []Scheme{scheme}, SessionPublicKey: keys.PublicKey, SessionExpiration: time.Hour, AccountID: "account", ServiceID: "service"}))
	return mw, mw.Protect(newPassthroughHandler())
}

func credentialRequest(method, field, value string) *http.Request {
	r := httptest.NewRequest(method, "https://example.com/", strings.NewReader(url.Values{field: {value}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.25:12345"
	return r
}

func TestCredentialAuthPOSTOnly(t *testing.T) {
	for _, field := range []string{"pin", "password"} {
		t.Run(field, func(t *testing.T) {
			_, handler := credentialHandler(t, field)
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodPost} {
				r := credentialRequest(method, field, "")
				r.URL.RawQuery = url.Values{field: {"842716"}}.Encode()
				resp := httptest.NewRecorder()
				handler.ServeHTTP(resp, r)
				assert.Equal(t, http.StatusUnauthorized, resp.Code, "%s query credentials must not authenticate", method)
				assert.Empty(t, resp.Result().Cookies(), "query credentials must not issue a session")
			}
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				resp := httptest.NewRecorder()
				handler.ServeHTTP(resp, credentialRequest(method, field, "842716"))
				assert.Equal(t, http.StatusUnauthorized, resp.Code, "%s body credentials must not authenticate", method)
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, credentialRequest(http.MethodPost, field, "842716"))
			assert.Equal(t, http.StatusSeeOther, resp.Code, "POST body credentials must authenticate")
		})
	}
}

func TestCredentialAuthThrottling(t *testing.T) {
	for _, field := range []string{"pin", "password"} {
		t.Run(field, func(t *testing.T) {
			_, handler := credentialHandler(t, field)
			for range 5 {
				resp := httptest.NewRecorder()
				handler.ServeHTTP(resp, credentialRequest(http.MethodPost, field, "000000"))
				require.Equal(t, http.StatusUnauthorized, resp.Code, "initial wrong credentials must be rejected")
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, credentialRequest(http.MethodPost, field, "842716"))
			assert.Equal(t, http.StatusTooManyRequests, resp.Code, "even correct credentials must wait for the block to expire")
			assert.Equal(t, "900", resp.Header().Get("Retry-After"), "five failures must block the source for fifteen minutes")
			assert.Empty(t, resp.Result().Cookies(), "blocked credentials must not issue a session")
		})
	}
}

func TestCredentialAuthSessionAndClientIP(t *testing.T) {
	keys := generateTestKeyPair(t)
	token, err := sessionkey.SignToken(keys.PrivateKey, "pin-user", "", "example.com", proxyauth.MethodPIN, nil, nil, time.Hour)
	require.NoError(t, err)
	mw := NewMiddleware(nil, nil, nil)
	now := time.Now()
	mw.credentials.now = func() time.Time { return now }
	scheme := &stubScheme{method: proxyauth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", DomainSettings{Schemes: []Scheme{scheme}, SessionPublicKey: keys.PublicKey, AccountID: "account", ServiceID: "service"}))
	handler := mw.Protect(newPassthroughHandler())
	for range credentialFailureLimit {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, credentialRequest(http.MethodPost, "pin", "000000"))
		require.Equal(t, http.StatusUnauthorized, resp.Code, "bad PIN must consume the failure budget")
	}
	now = now.Add(credentialCheckInterval)
	require.NoError(t, mw.AddDomain("example.com", DomainSettings{Schemes: []Scheme{scheme}, SessionPublicKey: keys.PublicKey, AccountID: "account", ServiceID: "service"}))
	r := credentialRequest(http.MethodPost, "pin", "000000")
	r.RemoteAddr = "[::ffff:198.51.100.25]:45678"
	r.Header.Set("X-Forwarded-For", "192.0.2.5")
	r.Header.Set("X-Real-IP", "192.0.2.6")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, r)
	assert.Equal(t, http.StatusTooManyRequests, resp.Code, "mapped addresses and untrusted forwarding headers must not bypass the source block")
	assert.Equal(t, "no-store", resp.Header().Get("Cache-Control"), "rate limits must not be cached")
	r.AddCookie(&http.Cookie{Name: proxyauth.SessionCookieName, Value: token})
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, r)
	assert.Equal(t, http.StatusOK, resp.Code, "an existing session must pass even with credentials in the request")
	assert.Equal(t, "backend", resp.Body.String(), "the authenticated request must reach the application")
	r = credentialRequest(http.MethodPost, "pin", "000000")
	cd := proxy.NewCapturedData("test")
	cd.SetClientIP(netip.MustParseAddr("192.0.2.9"))
	r = r.WithContext(proxy.WithCapturedData(r.Context(), cd))
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, r)
	assert.Equal(t, http.StatusUnauthorized, resp.Code, "a client resolved by the trusted-proxy middleware must get its own source budget")
	r = credentialRequest(http.MethodPost, "pin", "000000")
	r.RemoteAddr = "invalid"
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, r)
	assert.Equal(t, http.StatusBadRequest, resp.Code, "an unresolvable client address must fail closed")
	now = now.Add(credentialBlockDuration)
	scheme.token = token
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, credentialRequest(http.MethodPost, "pin", "842716"))
	assert.Equal(t, http.StatusSeeOther, resp.Code, "credentials must work again after cooldown")
}

func TestCredentialAuthManagementThrottling(t *testing.T) {
	s, err := status.New(codes.ResourceExhausted, "rate limited").WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(2500 * time.Millisecond)})
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		err   error
		code  int
		retry string
	}{
		{"retry info", fmt.Errorf("authenticate PIN: %w", s.Err()), http.StatusTooManyRequests, "3"},
		{"missing retry info", status.Error(codes.ResourceExhausted, "rate limited"), http.StatusTooManyRequests, "6"},
		{"unavailable", status.Error(codes.Unavailable, "unavailable"), http.StatusBadGateway, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := generateTestKeyPair(t)
			mw := NewMiddleware(nil, nil, nil)
			scheme := &stubScheme{method: proxyauth.MethodPIN, authFn: func(*http.Request) (string, string, error) { return "", "", tc.err }}
			require.NoError(t, mw.AddDomain("example.com", DomainSettings{Schemes: []Scheme{scheme}, SessionPublicKey: keys.PublicKey, AccountID: "account", ServiceID: "service"}))
			resp := httptest.NewRecorder()
			mw.Protect(newPassthroughHandler()).ServeHTTP(resp, credentialRequest(http.MethodPost, "pin", "000000"))
			assert.Equal(t, tc.code, resp.Code, "management errors must keep their HTTP meaning")
			assert.Equal(t, tc.retry, resp.Header().Get("Retry-After"), "retry hints must round up to whole seconds")
		})
	}
}
