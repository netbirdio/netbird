package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
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
	err := mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil)
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
	err := mw.AddDomain("example.com", []Scheme{scheme}, "", time.Hour, "", "", nil)
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
	err := mw.AddDomain("example.com", []Scheme{scheme}, "not-valid-base64!!!", time.Hour, "", "", nil)
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
	err := mw.AddDomain("example.com", []Scheme{scheme}, shortKey, time.Hour, "", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session public key size")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with a wrong-size key")
}

func TestAddDomain_NoSchemes_NoKeyRequired(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)

	err := mw.AddDomain("example.com", nil, "", time.Hour, "", "", nil)
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

	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp1.PublicKey, time.Hour, "", "", nil))
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp2.PublicKey, 2*time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", nil, "", time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "example.com", auth.MethodPIN, time.Hour)
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

func TestProtect_ExpiredSessionCookieIsRejected(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

	// Sign a token that expired 1 second ago.
	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "example.com", auth.MethodPIN, -time.Second)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

	// Token signed for a different domain audience.
	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "other.com", auth.MethodPIN, time.Hour)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp1.PublicKey, time.Hour, "", "", nil))

	// Token signed with a different private key.
	token, err := sessionkey.SignToken(kp2.PrivateKey, "test-user", "example.com", auth.MethodPIN, time.Hour)
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

	token, err := sessionkey.SignToken(kp.PrivateKey, "pin-user", "example.com", auth.MethodPIN, time.Hour)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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

func TestProtect_FailedAuthDoesNotSetCookie(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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

	token, err := sessionkey.SignToken(kp.PrivateKey, "password-user", "example.com", auth.MethodPassword, time.Hour)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{pinScheme, passwordScheme}, kp.PublicKey, time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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

	err = mw.AddDomain("example.com", []Scheme{scheme}, key, time.Hour, "", "", nil)
	require.NoError(t, err, "any 32-byte key should be accepted at registration time")
}

func TestAddDomain_InvalidKeyDoesNotCorruptExistingConfig(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

	// Attempt to overwrite with an invalid key.
	err := mw.AddDomain("example.com", []Scheme{scheme}, "bad", time.Hour, "", "", nil)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

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
		restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}}))
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
		restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"203.0.113.0/24"}}))
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
		restrict.ParseFilter(restrict.FilterConfig{AllowedCountries: []string{"US"}}))
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "", nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{oidcScheme, pinScheme}, kp.PublicKey, time.Hour, "", "", nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "should show login page when multiple methods exist")
}

// mockAuthenticator is a minimal mock for the authenticator gRPC interface
// used by the Header scheme.
type mockAuthenticator struct {
	fn func(ctx context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error)
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, in *proto.AuthenticateRequest, _ ...grpc.CallOption) (*proto.AuthenticateResponse, error) {
	return m.fn(ctx, in)
}

// newHeaderSchemeWithToken creates a Header scheme backed by a mock that
// returns a signed session token when the expected header value is provided.
func newHeaderSchemeWithToken(t *testing.T, kp *sessionkey.KeyPair, headerName, expectedValue string) Header {
	t.Helper()
	token, err := sessionkey.SignToken(kp.PrivateKey, "header-user", "example.com", auth.MethodHeader, time.Hour)
	require.NoError(t, err)

	mock := &mockAuthenticator{fn: func(_ context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
		ha := req.GetHeaderAuth()
		if ha != nil && ha.GetHeaderValue() == expectedValue {
			return &proto.AuthenticateResponse{Success: true, SessionToken: token}, nil
		}
		return &proto.AuthenticateResponse{Success: false}, nil
	}}
	return NewHeader(mock, "svc1", "acc1", headerName)
}

func TestProtect_HeaderAuth_ForwardsOnSuccess(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderSchemeWithToken(t, kp, "X-API-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil))

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

	// Session cookie should be set.
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie, "session cookie should be set after successful header auth")
	assert.True(t, sessionCookie.HttpOnly)
	assert.True(t, sessionCookie.Secure)

	assert.Equal(t, "header-user", capturedData.GetUserID())
	assert.Equal(t, "header", capturedData.GetAuthMethod())
}

func TestProtect_HeaderAuth_MissingHeaderFallsThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderSchemeWithToken(t, kp, "X-API-Key", "secret-key")
	// Also add a PIN scheme so we can verify fallthrough behavior.
	pinScheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr, pinScheme}, kp.PublicKey, time.Hour, "acc1", "svc1", nil))

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

	mock := &mockAuthenticator{fn: func(_ context.Context, _ *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
		return &proto.AuthenticateResponse{Success: false}, nil
	}}
	hdr := NewHeader(mock, "svc1", "acc1", "X-API-Key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil))

	capturedData := proxy.NewCapturedData("")
	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), capturedData))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "header", capturedData.GetAuthMethod())
}

func TestProtect_HeaderAuth_InfraErrorReturns502(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	mock := &mockAuthenticator{fn: func(_ context.Context, _ *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
		return nil, errors.New("gRPC unavailable")
	}}
	hdr := NewHeader(mock, "svc1", "acc1", "X-API-Key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-API-Key", "some-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestProtect_HeaderAuth_SubsequentRequestUsesSessionCookie(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	hdr := newHeaderSchemeWithToken(t, kp, "X-API-Key", "secret-key")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil))

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request with header auth.
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req1.Header.Set("X-API-Key", "secret-key")
	req1 = req1.WithContext(proxy.WithCapturedData(req1.Context(), proxy.NewCapturedData("")))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	// Extract session cookie.
	var sessionCookie *http.Cookie
	for _, c := range rec1.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie)

	// Second request with only the session cookie (no header).
	capturedData2 := proxy.NewCapturedData("")
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	req2.AddCookie(sessionCookie)
	req2 = req2.WithContext(proxy.WithCapturedData(req2.Context(), capturedData2))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "header-user", capturedData2.GetUserID())
	assert.Equal(t, "header", capturedData2.GetAuthMethod())
}

// TestProtect_HeaderAuth_MultipleValuesSameHeader verifies that the proxy
// correctly handles multiple valid credentials for the same header name.
// In production, the mgmt gRPC authenticateHeader iterates all configured
// header auths and accepts if any hash matches (OR semantics). The proxy
// creates one Header scheme per entry, but a single gRPC call checks all.
func TestProtect_HeaderAuth_MultipleValuesSameHeader(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)

	// Mock simulates mgmt behavior: accepts either token-a or token-b.
	accepted := map[string]bool{"Bearer token-a": true, "Bearer token-b": true}
	mock := &mockAuthenticator{fn: func(_ context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
		ha := req.GetHeaderAuth()
		if ha != nil && accepted[ha.GetHeaderValue()] {
			token, err := sessionkey.SignToken(kp.PrivateKey, "header-user", "example.com", auth.MethodHeader, time.Hour)
			require.NoError(t, err)
			return &proto.AuthenticateResponse{Success: true, SessionToken: token}, nil
		}
		return &proto.AuthenticateResponse{Success: false}, nil
	}}

	// Single Header scheme (as if one entry existed), but the mock checks both values.
	hdr := NewHeader(mock, "svc1", "acc1", "Authorization")
	require.NoError(t, mw.AddDomain("example.com", []Scheme{hdr}, kp.PublicKey, time.Hour, "acc1", "svc1", nil))

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
