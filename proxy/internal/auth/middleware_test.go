package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func generateTestKeyPair(t *testing.T) *sessionkey.KeyPair {
	t.Helper()
	kp, err := sessionkey.GenerateKeyPair()
	require.NoError(t, err)
	return kp
}

// stubScheme is a minimal Scheme implementation for testing.
type stubScheme struct {
	method   auth.Method
	token    string
	promptID string
	authFn   func(*http.Request) (string, string, error)
}

func (s *stubScheme) Type() auth.Method { return s.method }

func (s *stubScheme) Authenticate(r *http.Request) (string, string, error) {
	if s.authFn != nil {
		return s.authFn(r)
	}
	return s.token, s.promptID, nil
}

func newPassthroughHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend"))
	})
}

func TestAddDomain_ValidKey(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil)
	require.NoError(t, err)

	mw.domainsMux.RLock()
	config, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()

	assert.True(t, exists, "domain should be registered")
	assert.Len(t, config.Schemes, 1)
	assert.Equal(t, ed25519.PublicKeySize, len(config.SessionPublicKey))
	assert.Equal(t, time.Hour, config.SessionExpiration)
}

func TestAddDomain_EmptyKey(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, "", time.Hour, "", "", nil, false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session public key size")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with an empty session key")
}

func TestAddDomain_InvalidBase64(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, "not-valid-base64!!!", time.Hour, "", "", nil, false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode session public key")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with invalid base64 key")
}

func TestAddDomain_WrongKeySize(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, shortKey, time.Hour, "", "", nil, false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session public key size")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with a wrong-size key")
}

func TestAddDomain_NoSchemes_NoKeyRequired(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", time.Hour, "", "", nil, false, nil)
	require.NoError(t, err, "domains with no auth schemes should not require a key")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.True(t, exists)
}

func TestAddDomain_OverwritesPreviousConfig(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}

	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp1.PublicKey, time.Hour, "", "", nil, false, nil))
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp2.PublicKey, 2*time.Hour, "", "", nil, false, nil))

	mw.domainsMux.RLock()
	config := mw.domains["example.com"]
	mw.domainsMux.RUnlock()

	pubKeyBytes, _ := base64.StdEncoding.DecodeString(kp2.PublicKey)
	assert.Equal(t, ed25519.PublicKey(pubKeyBytes), config.SessionPublicKey, "should use the latest key")
	assert.Equal(t, 2*time.Hour, config.SessionExpiration)
}

func TestRemoveDomain(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	mw.RemoveDomain("example.com")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists)
}

func TestProtect_UnknownDomainPassesThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://unknown.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend", rec.Body.String())
}

func TestProtect_DomainWithNoSchemesPassesThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain("example.com", nil, "", time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend", rec.Body.String())
}

func TestProtect_UnauthenticatedRequestIsBlocked(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "unauthenticated request should not reach backend")
}

func TestProtect_HostWithPortIsMatched(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	req := httptest.NewRequest(http.MethodGet, "http://example.com:8443/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "host with port should still match the protected domain")
}

func TestProtect_ValidSessionCookiePassesThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "", "example.com", auth.MethodPIN, nil, nil, time.Hour)
	require.NoError(t, err)

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cd := proxy.CapturedDataFromContext(r.Context())
		require.NotNil(t, cd)
		assert.Equal(t, "test-user", cd.GetUserID())
		assert.Equal(t, "pin", cd.GetAuthMethod())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "authenticated", rec.Body.String())
}

// TestProtect_SessionCookieGroupsPropagate verifies the cookie path lifts the
// JWT's groups claim into CapturedData so policy-aware middlewares can
// authorise without an extra management round-trip.
func TestProtect_SessionCookieGroupsPropagate(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	groups := []string{"engineering", "sre"}
	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "", "example.com", auth.MethodPIN, groups, nil, time.Hour)
	require.NoError(t, err)

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cd := proxy.CapturedDataFromContext(r.Context())
		require.NotNil(t, cd, "captured data must be present in request context")
		assert.Equal(t, "test-user", cd.GetUserID())
		assert.Equal(t, groups, cd.GetUserGroups(), "JWT groups claim must propagate to CapturedData")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "request with valid groups-bearing cookie must succeed")
	assert.Equal(t, groups, capturedData.GetUserGroups(), "CapturedData groups must be retained after handler completes")
}

// stubTunnelValidator implements SessionValidator for the tunnel-peer
// path. ValidateTunnelPeer returns a fixed response so tests can assert
// how the proxy maps it onto CapturedData, and records whether the
// fast-path actually reached management.
type stubTunnelValidator struct {
	called bool
	resp   *proto.ValidateTunnelPeerResponse
}

func (s *stubTunnelValidator) ValidateSession(context.Context, *proto.ValidateSessionRequest, ...grpc.CallOption) (*proto.ValidateSessionResponse, error) {
	return nil, errors.New("not used in this test")
}

func (s *stubTunnelValidator) ValidateTunnelPeer(context.Context, *proto.ValidateTunnelPeerRequest, ...grpc.CallOption) (*proto.ValidateTunnelPeerResponse, error) {
	s.called = true
	return s.resp, nil
}

// TestProtect_PrivateService_TunnelPeerGroupsPropagate locks the agent-network
// auth path end-to-end at the proxy edge: a Private service must route through
// ValidateTunnelPeer and lift the returned peer_group_ids onto CapturedData so
// the llm_router group-authorisation pass can see them. Regression guard for
// the failure that surfaces downstream as llm_policy.no_authorised_provider —
// i.e. a synthesised service that reaches the proxy without private=true (so
// this path is skipped) leaves UserGroups empty and every request is denied.
func TestProtect_PrivateService_TunnelPeerGroupsPropagate(t *testing.T) {
	groups := []string{"grp-admins", "grp-users"}
	names := []string{"Admins", "Users"}
	validator := &stubTunnelValidator{resp: &proto.ValidateTunnelPeerResponse{
		Valid:          true,
		UserId:         "user-1",
		UserEmail:      "user@example.com",
		SessionToken:   "tunnel-session-token",
		PeerGroupIds:   groups,
		PeerGroupNames: names,
	}}
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)

	// Private service: no operator schemes — auth gates solely on the tunnel peer.
	require.NoError(t, mw.AddDomain("agent.example.com", nil, kp.PublicKey, time.Hour, "acct-1", "svc-1", nil, true, nil))

	cd := proxy.NewCapturedData("")
	cd.SetClientIP(netip.MustParseAddr("100.90.1.14")) // CGNAT tunnel source

	var seenGroups []string
	var seenUser string
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := proxy.CapturedDataFromContext(r.Context())
		require.NotNil(t, c, "captured data must be present in request context")
		seenGroups = c.GetUserGroups()
		seenUser = c.GetUserID()
		w.WriteHeader(http.StatusOK)
	}))

	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})
	req := httptest.NewRequest(http.MethodPost, "http://agent.example.com/v1/chat/completions", nil)
	req.RemoteAddr = "100.90.1.14:5000"
	req = req.WithContext(WithTunnelLookup(proxy.WithCapturedData(req.Context(), cd), lookup))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "private service must authorise a tunnel peer the validator accepts")
	assert.Equal(t, groups, seenGroups, "ValidateTunnelPeer peer_group_ids must reach CapturedData.UserGroups for llm_router authorisation")
	assert.Equal(t, "user-1", seenUser, "tunnel-peer principal must reach CapturedData")
	assert.Equal(t, groups, cd.GetUserGroups(), "groups must persist on CapturedData after the handler returns")
}

// TestProtect_PrivateService_TunnelPeerDenied verifies the deny path: when
// ValidateTunnelPeer rejects the peer, a Private service 403s and never reaches
// the upstream handler (no fall-through to unauthenticated pass-through).
func TestProtect_PrivateService_TunnelPeerDenied(t *testing.T) {
	validator := &stubTunnelValidator{resp: &proto.ValidateTunnelPeerResponse{
		Valid:        false,
		DeniedReason: "not_in_group",
	}}
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)
	require.NoError(t, mw.AddDomain("agent.example.com", nil, kp.PublicKey, time.Hour, "acct-1", "svc-1", nil, true, nil))

	cd := proxy.NewCapturedData("")
	cd.SetClientIP(netip.MustParseAddr("100.90.1.14"))

	reached := false
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})
	req := httptest.NewRequest(http.MethodPost, "http://agent.example.com/v1/chat/completions", nil)
	req.RemoteAddr = "100.90.1.14:5000"
	req = req.WithContext(WithTunnelLookup(proxy.WithCapturedData(req.Context(), cd), lookup))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "private service must 403 when the tunnel peer is rejected")
	assert.False(t, reached, "denied private request must not reach the upstream handler")
}

func TestProtect_ExpiredSessionCookieIsRejected(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	// Sign a token that expired 1 second ago.
	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "", "example.com", auth.MethodPIN, nil, nil, -time.Second)
	require.NoError(t, err)

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "expired session should not reach the backend")
}

func TestProtect_WrongDomainCookieIsRejected(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	// Token signed for a different domain audience.
	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "", "other.com", auth.MethodPIN, nil, nil, time.Hour)
	require.NoError(t, err)

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "cookie for wrong domain should be rejected")
}

func TestProtect_WrongKeyCookieIsRejected(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp1.PublicKey, time.Hour, "", "", nil, false, nil))

	// Token signed with a different private key.
	token, err := sessionkey.SignToken(kp2.PrivateKey, "test-user", "", "example.com", auth.MethodPIN, nil, nil, time.Hour)
	require.NoError(t, err)

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "cookie signed by wrong key should be rejected")
}

func TestProtect_SchemeAuthRedirectsWithCookie(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	token, err := sessionkey.SignToken(kp.PrivateKey, "pin-user", "", "example.com", auth.MethodPIN, nil, nil, time.Hour)
	require.NoError(t, err)

	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(r *http.Request) (string, string, error) {
			if r.FormValue("pin") == "111111" {
				return token, "", nil
			}
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	// Submit the PIN via form POST.
	form := url.Values{"pin": {"111111"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/somepath", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "backend should not be called during auth, only a redirect should be returned")
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/somepath", rec.Header().Get("Location"), "redirect should point to the original request URI")

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie, "session cookie should be set after successful auth")
	assert.True(t, sessionCookie.HttpOnly)
	assert.True(t, sessionCookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, sessionCookie.SameSite)
}

func TestSetSessionCookieHasRootPath(t *testing.T) {
	w := httptest.NewRecorder()
	setSessionCookie(w, "test-token", time.Hour)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "/", cookies[0].Path, "session cookie must be scoped to root so it applies to all paths")
}

func TestProtect_FailedAuthDoesNotSetCookie(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, auth.SessionCookieName, c.Name, "no session cookie should be set on failed auth")
	}
}

func TestProtect_MultipleSchemes(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	token, err := sessionkey.SignToken(kp.PrivateKey, "password-user", "", "example.com", auth.MethodPassword, nil, nil, time.Hour)
	require.NoError(t, err)

	// First scheme (PIN) always fails, second scheme (password) succeeds.
	pinScheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	passwordScheme := &stubScheme{
		method: auth.MethodPassword,
		authFn: func(r *http.Request) (string, string, error) {
			if r.FormValue("password") == "secret" {
				return token, "", nil
			}
			return "", "password", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{pinScheme, passwordScheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	var backendCalled bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Protect(backend)

	form := url.Values{"password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled, "backend should not be called during auth")
	assert.Equal(t, http.StatusSeeOther, rec.Code)
}

func TestProtect_InvalidTokenFromSchemeReturns400(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	// Return a garbage token that won't validate.
	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "invalid-jwt-token", "", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAddDomain_RandomBytes32NotEd25519(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	// 32 random bytes that happen to be valid base64 and correct size
	// but are actually a valid ed25519 public key length-wise.
	// This should succeed because ed25519 public keys are just 32 bytes.
	randomBytes := make([]byte, ed25519.PublicKeySize)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)

	key := base64.StdEncoding.EncodeToString(randomBytes)
	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}

	err = mw.AddDomain("example.com", []Scheme{scheme}, key, time.Hour, "", "", nil, false, nil)
	require.NoError(t, err, "any 32-byte key should be accepted at registration time")
}

func TestAddDomain_InvalidKeyDoesNotCorruptExistingConfig(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	// Attempt to overwrite with an invalid key.
	err := mw.AddDomain("example.com", []Scheme{scheme}, "bad", time.Hour, "", "", nil, false, nil)
	require.Error(t, err)

	// The original valid config should still be intact.
	mw.domainsMux.RLock()
	config, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()

	assert.True(t, exists, "original config should still exist")
	assert.Len(t, config.Schemes, 1)
	assert.Equal(t, time.Hour, config.SessionExpiration)
}

func TestProtect_FailedPinAuthCapturesAuthMethod(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	// Scheme that always fails authentication (returns empty token)
	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(newPassthroughHandler())

	// Submit wrong PIN - should capture auth method
	form := url.Values{"pin": {"wrong-pin"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "pin", capturedData.GetAuthMethod(), "Auth method should be captured for failed PIN auth")
}

func TestProtect_FailedPasswordAuthCapturesAuthMethod(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPassword,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "password", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(newPassthroughHandler())

	// Submit wrong password - should capture auth method
	form := url.Values{"password": {"wrong-password"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "password", capturedData.GetAuthMethod(), "Auth method should be captured for failed password auth")
}

func TestProtect_NoCredentialsDoesNotCaptureAuthMethod(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(newPassthroughHandler())

	// No credentials submitted - should not capture auth method
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, capturedData.GetAuthMethod(), "Auth method should not be captured when no credentials submitted")
}

func TestWasCredentialSubmitted(t *testing.T) {
	tests := []struct {
		name     string
		method   auth.Method
		formData url.Values
		query    url.Values
		expected bool
	}{
		{
			name:     "PIN submitted",
			method:   auth.MethodPIN,
			formData: url.Values{"pin": {"123456"}},
			expected: true,
		},
		{
			name:     "PIN not submitted",
			method:   auth.MethodPIN,
			formData: url.Values{},
			expected: false,
		},
		{
			name:     "Password submitted",
			method:   auth.MethodPassword,
			formData: url.Values{"password": {"secret"}},
			expected: true,
		},
		{
			name:     "Password not submitted",
			method:   auth.MethodPassword,
			formData: url.Values{},
			expected: false,
		},
		{
			name:     "OIDC token in query",
			method:   auth.MethodOIDC,
			query:    url.Values{"session_token": {"abc123"}},
			expected: true,
		},
		{
			name:     "OIDC token not in query",
			method:   auth.MethodOIDC,
			query:    url.Values{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := "http://example.com/"
			if len(tt.query) > 0 {
				reqURL += "?" + tt.query.Encode()
			}

			var body *strings.Reader
			if len(tt.formData) > 0 {
				body = strings.NewReader(tt.formData.Encode())
			} else {
				body = strings.NewReader("")
			}

			req := httptest.NewRequest(http.MethodPost, reqURL, body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			result := wasCredentialSubmitted(req, tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckIPRestrictions_UnparseableAddress(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", 0, "acc1", "svc1",
		restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}}), false, nil)
	require.NoError(t, err)

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
	}{
		{"unparsable address denies", "not-an-ip:1234", http.StatusForbidden},
		{"empty address denies", "", http.StatusForbidden},
		{"allowed address passes", "10.1.2.3:5678", http.StatusOK},
		{"denied address blocked", "192.168.1.1:5678", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Host = "example.com"
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tt.wantCode, rr.Code)
		})
	}
}

func TestCheckIPRestrictions_UsesCapturedDataClientIP(t *testing.T) {
	// When CapturedData is set (by the access log middleware, which resolves
	// trusted proxies), checkIPRestrictions should use that IP, not RemoteAddr.
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", 0, "acc1", "svc1",
		restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"203.0.113.0/24"}}), false, nil)
	require.NoError(t, err)

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// RemoteAddr is a trusted proxy, but CapturedData has the real client IP.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Host = "example.com"

	cd := proxy.NewCapturedData("")
	cd.SetClientIP(netip.MustParseAddr("203.0.113.50"))
	ctx := proxy.WithCapturedData(req.Context(), cd)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "should use CapturedData IP (203.0.113.50), not RemoteAddr (10.0.0.1)")

	// Same request but CapturedData has a blocked IP.
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2.RemoteAddr = "203.0.113.50:5000"
	req2.Host = "example.com"

	cd2 := proxy.NewCapturedData("")
	cd2.SetClientIP(netip.MustParseAddr("10.0.0.1"))
	ctx2 := proxy.WithCapturedData(req2.Context(), cd2)
	req2 = req2.WithContext(ctx2)

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code, "should use CapturedData IP (10.0.0.1), not RemoteAddr (203.0.113.50)")
}

func TestCheckIPRestrictions_NilGeoWithCountryRules(t *testing.T) {
	// Geo is nil, country restrictions are configured: must deny (fail-close).
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", 0, "acc1", "svc1",
		restrict.ParseFilter(restrict.FilterConfig{AllowedCountries: []string{"US"}}), false, nil)
	require.NoError(t, err)

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code, "country restrictions with nil geo must deny")
}

// TestCheckIPRestrictions_OverlayOriginSkipsCountryRules covers the
// inbound (WG) listener path: requests stamped with WithOverlayOrigin
// must skip country lookups, even when no geo database is configured.
// Without this short-circuit the inbound flow would fail-closed for
// every overlay request whenever country rules are configured.
func TestCheckIPRestrictions_OverlayOriginSkipsCountryRules(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", 0, "acc1", "svc1",
		restrict.ParseFilter(restrict.FilterConfig{
			AllowedCIDRs:     []string{"100.64.0.0/10"},
			AllowedCountries: []string{"US"},
		}), false, nil)
	require.NoError(t, err)

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "100.64.5.6:5000"
	req.Host = "example.com"
	req = req.WithContext(types.WithOverlayOrigin(req.Context()))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code,
		"overlay-origin requests must not be denied by country rules they would fail without geo data")

	// Sanity check: the same filter without the overlay flag denies (no geo,
	// country allowlist active → DenyGeoUnavailable).
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2.RemoteAddr = "100.64.5.6:5000"
	req2.Host = "example.com"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code,
		"WAN-origin requests must still hit the full Check path and be denied without geo data")
}

// TestCheckIPRestrictions_OverlayOriginRespectsCIDR confirms CIDR
// rules still apply on the overlay path so operators retain a way to
// scope private services to specific peer subnets.
func TestCheckIPRestrictions_OverlayOriginRespectsCIDR(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", 0, "acc1", "svc1",
		restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"100.64.0.0/16"}}), false, nil)
	require.NoError(t, err)

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "100.65.5.6:5000" // outside 100.64.0.0/16
	req.Host = "example.com"
	req = req.WithContext(types.WithOverlayOrigin(req.Context()))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code,
		"CIDR rules must still apply on the overlay path")
}

func TestProtect_OIDCOnlyRedirectsDirectly(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	oidcURL := "https://idp.example.com/authorize?client_id=abc"
	scheme := &stubScheme{
		method: auth.MethodOIDC,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", oidcURL, nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code, "should redirect directly to IdP")
	assert.Equal(t, oidcURL, rec.Header().Get("Location"))
}

func TestProtect_OIDCWithOtherMethodShowsLoginPage(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	oidcScheme := &stubScheme{
		method: auth.MethodOIDC,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "https://idp.example.com/authorize", nil
		},
	}
	pinScheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{oidcScheme, pinScheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "should show login page when multiple methods exist")
}

// newHeaderScheme creates a Header scheme accepting each of the given values,
// hashed the way management hashes them before putting them on the mapping.
func newHeaderScheme(t *testing.T, headerName string, acceptedValues ...string) Header {
	t.Helper()
	hashes := make([]string, 0, len(acceptedValues))
	for _, v := range acceptedValues {
		hash, err := argon2id.Hash(v)
		require.NoError(t, err, "hashing an accepted header value must succeed")
		hashes = append(hashes, hash)
	}
	return NewHeader(headerName, hashes)
}

func TestProtect_HeaderAuth_ForwardsOnSuccess(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "X-API-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	var backendCalled bool
	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header.Set("X-API-Key", "secret-key")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, backendCalled, "backend should be called directly for header auth (no redirect)")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())

	// The credential rides on every request, so no session cookie is issued.
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, auth.SessionCookieName, c.Name, "header auth must not issue a session cookie")
	}

	assert.Equal(t, auth.HeaderUserID, capturedData.GetUserID())
	assert.Equal(t, "header", capturedData.GetAuthMethod())
}

func TestProtect_HeaderAuth_MissingHeaderFallsThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "X-API-Key", "secret-key")
	// Also add a PIN scheme so we can verify fallthrough behavior.
	pinScheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr, pinScheme}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	// No X-API-Key header: should fall through to PIN login page (401).
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "missing header should fall through to login page")
}

func TestProtect_HeaderAuth_WrongValueReturns401(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "X-API-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "header", capturedData.GetAuthMethod())
	assert.Empty(t, hdr.verified.seen, "a rejected value must not be memoized")
}

// TestProtect_HeaderAuth_MatchesAnyConfiguredHeader covers a client that carries
// a valid credential on one configured header while also sending an unrelated
// value on another — an app-level Authorization alongside an API key, say.
// Schemes OR across header names, so the valid credential admits the request no
// matter which order the mapping happened to list the headers in.
func TestProtect_HeaderAuth_MatchesAnyConfiguredHeader(t *testing.T) {
	tests := []struct {
		name        string
		matchedLast bool
	}{
		{name: "unmatched header listed first", matchedLast: true},
		{name: "matched header listed first", matchedLast: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewMiddleware(log.StandardLogger(), nil, nil)
			kp := generateTestKeyPair(t)

			authz := newHeaderScheme(t, "Authorization", "Bearer proxy-secret")
			apiKey := newHeaderScheme(t, "X-Api-Key", "secret-key")
			schemes := []Scheme{apiKey, authz}
			if tt.matchedLast {
				schemes = []Scheme{authz, apiKey}
			}
			require.NoError(t, mw.AddDomain("example.com", schemes, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

			var backendCalled bool
			handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				backendCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.Header.Set("X-Api-Key", "secret-key")
			req.Header.Set("Authorization", "Bearer app-level-token")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.True(t, backendCalled, "a valid credential on one header must admit the request")
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

// TestProtect_HeaderAuth_RejectsWhenEveryPresentedHeaderFails is the other half
// of the OR: trying all schemes before rejecting must not turn into admitting a
// request that satisfied none of them.
func TestProtect_HeaderAuth_RejectsWhenEveryPresentedHeaderFails(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	authz := newHeaderScheme(t, "Authorization", "Bearer proxy-secret")
	apiKey := newHeaderScheme(t, "X-Api-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{authz, apiKey}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	var backendCalled bool
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Api-Key", "wrong-key")
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, backendCalled)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestProtect_HeaderAuth_ReportsUndecodableHash covers a stored hash the proxy
// cannot decode. No credential can ever match it, so the header is permanently
// unauthenticatable — an operator fault that has to surface loudly instead of
// hiding behind the same quiet 401 a wrong credential earns.
func TestProtect_HeaderAuth_ReportsUndecodableHash(t *testing.T) {
	validHash, err := argon2id.Hash("secret-key")
	require.NoError(t, err)

	tests := []struct {
		name       string
		hashes     []string
		wantErrLog bool
	}{
		{name: "stored hash cannot be decoded", hashes: []string{"$argon2id$v=19$garbage"}, wantErrLog: true},
		{name: "wrong credential against a good hash", hashes: []string{validHash}, wantErrLog: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()
			logger.SetLevel(log.DebugLevel)
			mw := NewMiddleware(logger, nil, nil)
			kp := generateTestKeyPair(t)

			require.NoError(t, mw.AddDomain("example.com", []Scheme{NewHeader("X-Api-Key", tt.hashes)},
				kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

			handler := mw.Protect(newPassthroughHandler())

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.Header.Set("X-Api-Key", "wrong-key")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equal(t, http.StatusUnauthorized, rec.Code, "either way the request is denied")

			var errored []string
			for _, entry := range hook.AllEntries() {
				if entry.Level == log.ErrorLevel {
					errored = append(errored, entry.Message)
				}
			}

			if !tt.wantErrLog {
				assert.Empty(t, errored, "a wrong credential is not an operator fault")
				return
			}
			require.Len(t, errored, 1, "an undecodable hash must be reported once")
			assert.Contains(t, errored[0], "cannot be decoded")
		})
	}
}

// TestProtect_HeaderAuth_NoHashesFailsClosed covers a mapping that names a
// header but carries no hash for it: the check cannot be evaluated, so the
// request must be denied rather than let through unauthenticated.
func TestProtect_HeaderAuth_NoHashesFailsClosed(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := NewHeader("X-API-Key", nil)
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	var backendCalled bool
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-API-Key", "any-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, backendCalled, "a header auth with no hashes must not admit the request")
}

// TestProtect_HeaderAuth_SubsequentRequestRequiresHeader verifies that header
// auth grants no ambient session: a follow-up request that drops the header is
// treated as unauthenticated.
func TestProtect_HeaderAuth_SubsequentRequestRequiresHeader(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "X-API-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	var backendCalls int
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req1.Header.Set("X-API-Key", "secret-key")
	req1 = req1.WithContext(proxy.WithCapturedData(req1.Context(), proxy.NewCapturedData("")))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)
	require.Equal(t, 1, backendCalls)

	// Same client, second request, header omitted: no cookie was handed out, so
	// there is nothing to carry the earlier success forward.
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	for _, c := range rec1.Result().Cookies() {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusUnauthorized, rec2.Code, "dropping the header must revoke access")
	assert.Equal(t, 1, backendCalls, "backend must not be reached without the header")
}

// TestProtect_HeaderAuth_LegacySessionCookieIsIgnored covers the upgrade
// window. Header auth used to mint a session token, so cookies with
// method=header survive a proxy upgrade and stay signature-valid for their full
// lifetime. They must not stand in for the header, or a credential rotated
// right after the upgrade would keep working until every such token expired.
func TestProtect_HeaderAuth_LegacySessionCookieIsIgnored(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "X-API-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	// A token management would have minted for header auth before the upgrade.
	legacyToken, err := sessionkey.SignToken(kp.PrivateKey, auth.HeaderUserID, "", "example.com", auth.MethodHeader, nil, nil, time.Hour)
	require.NoError(t, err)

	var backendCalls int
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("cookie alone is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: legacyToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "a header-auth cookie must not authenticate on its own")
		assert.Equal(t, 0, backendCalls, "backend must not be reached without the header")
	})

	t.Run("cookie does not block the header path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: legacyToken})
		req.Header.Set("X-API-Key", "secret-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "a client sending both must still be admitted by the header")
		assert.Equal(t, 1, backendCalls)
	})
}

// TestProtect_HeaderAuth_RepeatedValueIsMemoized verifies the KDF is run once
// per distinct accepted value. argon2id is deliberately expensive, so a
// credential that repeats on every request must not be re-derived each time.
func TestProtect_HeaderAuth_RepeatedValueIsMemoized(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "X-API-Key", "key-a", "key-b")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	get := func(value string) int {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("X-API-Key", value)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusOK, get("key-a"))
	require.Equal(t, http.StatusOK, get("key-a"))
	assert.Len(t, hdr.verified.seen, 1, "the same value must be memoized once")

	require.Equal(t, http.StatusOK, get("key-b"))
	assert.Len(t, hdr.verified.seen, 2, "each accepted value gets its own entry")

	require.Equal(t, http.StatusUnauthorized, get("key-c"))
	assert.Len(t, hdr.verified.seen, 2, "rejected values must not grow the set")
}

// TestProtect_HeaderAuth_MultipleValuesSameHeader verifies that a service with
// several accepted credentials for one header name accepts any of them.
// Management applied these OR semantics while it still validated the value; the
// proxy preserves them by carrying every hash for a name on one scheme.
func TestProtect_HeaderAuth_MultipleValuesSameHeader(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderScheme(t, "Authorization", "Bearer token-a", "Bearer token-b")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil))

	var backendCalled bool
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("first value accepted", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Authorization", "Bearer token-a")
		req = req.WithContext(proxy.WithCapturedData(req.Context(), proxy.NewCapturedData("")))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, backendCalled, "first token should be accepted")
	})

	t.Run("second value accepted", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Authorization", "Bearer token-b")
		req = req.WithContext(proxy.WithCapturedData(req.Context(), proxy.NewCapturedData("")))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, backendCalled, "second token should be accepted")
	})

	t.Run("unknown value rejected", func(t *testing.T) {
		backendCalled = false
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Authorization", "Bearer token-c")
		req = req.WithContext(proxy.WithCapturedData(req.Context(), proxy.NewCapturedData("")))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, backendCalled, "unknown token should be rejected")
	})
}

// TestProtect_OIDCOnPlainHTTP_BlockedWith400 verifies that when an OIDC
// scheme is configured and the request arrived without TLS, the middleware
// short-circuits with a 400 instead of dispatching to the IdP redirect.
func TestProtect_OIDCOnPlainHTTP_BlockedWith400(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodOIDC,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "https://idp.example.com/authorize", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "OIDC over plain HTTP should be rejected")
	assert.Contains(t, rec.Body.String(), "OIDC requires TLS", "response body should explain the rejection")
}

// TestProtect_OIDCOverTLS_NotBlocked confirms the same configuration works
// over TLS — the block only fires on plain HTTP.
func TestProtect_OIDCOverTLS_NotBlocked(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodOIDC,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "https://idp.example.com/authorize", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code, "OIDC over TLS should redirect to IdP")
}

// TestProtect_NonOIDCSchemes_PlainHTTP_NotBlocked confirms that the OIDC
// block only fires when an OIDC scheme is configured. PIN-only domains
// pass through normally on plain HTTP.
func TestProtect_NonOIDCSchemes_PlainHTTP_NotBlocked(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "PIN-only domain should serve the login page on plain HTTP")
}

// TestProtect_TunnelPeerFastPath_RequiresInboundMarker guards the
// anti-spoof gate: a request with an RFC1918 source IP arriving on the
// public listener (no TunnelLookupFromContext attached) must not be
// allowed to take the tunnel-peer fast-path. Without this gate a public
// client whose source IP happens to fall inside an RFC1918 range could
// bypass the configured auth scheme by colliding with a known tunnel
// IP.
func TestProtect_TunnelPeerFastPath_RequiresInboundMarker(t *testing.T) {
	validator := &stubTunnelValidator{
		resp: &proto.ValidateTunnelPeerResponse{
			Valid:        true,
			SessionToken: "should-not-be-used",
			UserId:       "user-1",
		},
	}
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	// Request from an RFC1918 source IP on the public listener — no
	// TunnelLookupFromContext attached. The fast-path must reject this
	// and fall through to the PIN scheme (which renders 401 on plain
	// HTTP for a non-authenticated request).
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "100.64.0.5:5000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, validator.called,
		"ValidateTunnelPeer must not be invoked when the request lacks the inbound TunnelLookup marker")
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"without the inbound marker the request must fall through to the operator auth scheme")
}

// TestProtect_TunnelPeerFastPath_TakesPathWithInboundMarker verifies
// the positive side: a request marked as overlay-origin (carrying the
// TunnelLookup context value) and matching a tunnel-IP range does take
// the fast-path and reach management.
func TestProtect_TunnelPeerFastPath_TakesPathWithInboundMarker(t *testing.T) {
	validator := &stubTunnelValidator{
		resp: &proto.ValidateTunnelPeerResponse{
			Valid:        true,
			SessionToken: "tunnel-session-token",
			UserId:       "user-1",
		},
	}
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil, false, nil))

	handler := mw.Protect(newPassthroughHandler())

	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "100.64.0.5:5000"
	req = req.WithContext(WithTunnelLookup(req.Context(), lookup))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, validator.called,
		"ValidateTunnelPeer must run when the request carries the inbound TunnelLookup marker")
	assert.Equal(t, http.StatusOK, rec.Code,
		"a successful tunnel-peer validation must forward to the next handler")
}
