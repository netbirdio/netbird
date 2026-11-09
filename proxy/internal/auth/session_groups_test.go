package auth

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// denyingSessionValidator mimics management for a user who completed OIDC login
// but is outside the service's distribution groups: ValidateSession denies.
type denyingSessionValidator struct {
	calls int
}

func (d *denyingSessionValidator) ValidateSession(context.Context, *proto.ValidateSessionRequest, ...grpc.CallOption) (*proto.ValidateSessionResponse, error) {
	d.calls++
	return &proto.ValidateSessionResponse{Valid: false, UserId: "user-1", DeniedReason: "not_in_group"}, nil
}

func (d *denyingSessionValidator) ValidateTunnelPeer(context.Context, *proto.ValidateTunnelPeerRequest, ...grpc.CallOption) (*proto.ValidateTunnelPeerResponse, error) {
	return &proto.ValidateTunnelPeerResponse{Valid: false}, nil
}

// TestProtect_SelfInstalledCookieCannotBypassGroupCheck is the regression guard
// for the group-authorisation bypass: a user denied at login still holds the raw
// session token from the ?session_token= redirect, so pasting it into the
// nb_session cookie must not buy access. The cookie path validated only the JWT
// signature, which turned the token management had already refused into a bearer
// credential for the service.
func TestProtect_SelfInstalledCookieCannotBypassGroupCheck(t *testing.T) {
	validator := &denyingSessionValidator{}
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)

	oidc := &stubScheme{method: auth.MethodOIDC, authFn: func(r *http.Request) (string, string, error) {
		return r.URL.Query().Get("session_token"), "https://idp.example/authorize", nil
	}}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{oidc}, kp.PublicKey, time.Hour, "acct-1", "svc-1", nil, false, []string{"grp-allowed"}))

	// The token a denied user gets to see: validly signed for this service and
	// domain, but carrying no group the service allows.
	token, err := sessionkey.SignToken(kp.PrivateKey, "user-1", "john.doe@example.com", "example.com", auth.MethodOIDC, nil, nil, time.Hour)
	require.NoError(t, err)

	backendHits := 0
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits++
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("token in the callback URL is denied", func(t *testing.T) {
		rec := serveWithCookie(t, handler, "https://example.com/?session_token="+token, nil)

		assert.Equal(t, http.StatusForbidden, rec.Code, "group check must deny the login")
		assert.Empty(t, rec.Result().Cookies(), "a denied login must not install a session cookie")
	})

	t.Run("same token pasted into the session cookie is denied", func(t *testing.T) {
		rec := serveWithCookie(t, handler, "https://example.com/", &http.Cookie{Name: auth.SessionCookieName, Value: token})

		assert.NotEqual(t, http.StatusOK, rec.Code, "a self-installed cookie must not reach the backend")
		assert.Equal(t, 0, backendHits, "backend must never be reached without an allowed group")
	})
}

// TestProtect_SessionCookieWithAllowedGroupPassesThrough is the positive half of
// the group gate: a member of an allowed group keeps the cookie fast-path, with
// no management round-trip.
func TestProtect_SessionCookieWithAllowedGroupPassesThrough(t *testing.T) {
	validator := &denyingSessionValidator{}
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)

	oidc := &stubScheme{method: auth.MethodOIDC}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{oidc}, kp.PublicKey, time.Hour, "acct-1", "svc-1", nil, false, []string{"grp-other", "grp-allowed"}))

	token, err := sessionkey.SignToken(kp.PrivateKey, "user-2", "jane@example.com", "example.com", auth.MethodOIDC,
		[]string{"grp-unrelated", "grp-allowed"}, []string{"Unrelated", "Allowed"}, time.Hour)
	require.NoError(t, err)

	handler := mw.Protect(newPassthroughHandler())
	rec := serveWithCookie(t, handler, "https://example.com/", &http.Cookie{Name: auth.SessionCookieName, Value: token})

	assert.Equal(t, http.StatusOK, rec.Code, "a cookie carrying an allowed group must pass through")
	assert.Equal(t, 0, validator.calls, "the cookie fast-path must not call management")
}

// TestProtect_NonOIDCSessionCookieIgnoresGroupRestriction locks the scope of the
// gate: PIN, password and header credentials carry no group identity and are
// authorised by the secret itself, exactly as management validates them.
func TestProtect_NonOIDCSessionCookieIgnoresGroupRestriction(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "acct-1", "svc-1", nil, false, []string{"grp-allowed"}))

	token, err := sessionkey.SignToken(kp.PrivateKey, "pin-user", "", "example.com", auth.MethodPIN, nil, nil, time.Hour)
	require.NoError(t, err)

	handler := mw.Protect(newPassthroughHandler())
	rec := serveWithCookie(t, handler, "https://example.com/", &http.Cookie{Name: auth.SessionCookieName, Value: token})

	assert.Equal(t, http.StatusOK, rec.Code, "a PIN session must not be gated on OIDC group membership")
}

func TestSessionGroupsAllowed(t *testing.T) {
	allowed := groupSet([]string{"a", "b"})

	tests := []struct {
		name    string
		allowed map[string]struct{}
		method  auth.Method
		groups  []string
		want    bool
	}{
		{"unrestricted service allows a groupless token", nil, auth.MethodOIDC, nil, true},
		{"restricted service allows an intersecting token", allowed, auth.MethodOIDC, []string{"c", "b"}, true},
		{"restricted service denies a disjoint token", allowed, auth.MethodOIDC, []string{"c"}, false},
		{"restricted service denies a groupless token", allowed, auth.MethodOIDC, nil, false},
		{"restricted service ignores a pin token", allowed, auth.MethodPIN, nil, true},
		{"restricted service ignores a password token", allowed, auth.MethodPassword, nil, true},
		{"restricted service ignores a header token", allowed, auth.MethodHeader, nil, true},
		{"restricted service denies an unknown method", allowed, auth.Method("totp"), []string{"a"}, false},
		{"restricted service denies a token with no method", allowed, auth.Method(""), []string{"a"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sessionGroupsAllowed(tc.allowed, tc.method, tc.groups))
		})
	}
}

func TestGroupSetDropsEmptyEntries(t *testing.T) {
	assert.Nil(t, groupSet(nil), "no groups means unrestricted")
	assert.Nil(t, groupSet([]string{"", ""}), "blank ids must not restrict access to nothing reachable")
	assert.Equal(t, map[string]struct{}{"a": {}}, groupSet([]string{"a", ""}))
}

// serveWithCookie drives the middleware over TLS with captured data attached,
// optionally carrying a session cookie.
func serveWithCookie(t *testing.T, handler http.Handler, url string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.TLS = &tls.ConnectionState{}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req = req.WithContext(proxy.WithCapturedData(req.Context(), proxy.NewCapturedData("")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
