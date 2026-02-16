package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", "")
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
	mw := NewMiddleware(log.StandardLogger(), nil)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, "", time.Hour, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session public key size")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with an empty session key")
}

func TestAddDomain_InvalidBase64(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, "not-valid-base64!!!", time.Hour, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode session public key")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with invalid base64 key")
}

func TestAddDomain_WrongKeySize(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)

	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	err := mw.AddDomain("example.com", []Scheme{scheme}, shortKey, time.Hour, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session public key size")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists, "domain must not be registered with a wrong-size key")
}

func TestAddDomain_NoSchemes_NoKeyRequired(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)

	err := mw.AddDomain("example.com", nil, "", time.Hour, "", "")
	require.NoError(t, err, "domains with no auth schemes should not require a key")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.True(t, exists)
}

func TestAddDomain_OverwritesPreviousConfig(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}

	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp1.PublicKey, time.Hour, "", ""))
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp2.PublicKey, 2*time.Hour, "", ""))

	mw.domainsMux.RLock()
	config := mw.domains["example.com"]
	mw.domainsMux.RUnlock()

	pubKeyBytes, _ := base64.StdEncoding.DecodeString(kp2.PublicKey)
	assert.Equal(t, ed25519.PublicKey(pubKeyBytes), config.SessionPublicKey, "should use the latest key")
	assert.Equal(t, 2*time.Hour, config.SessionExpiration)
}

func TestRemoveDomain(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	mw.RemoveDomain("example.com")

	mw.domainsMux.RLock()
	_, exists := mw.domains["example.com"]
	mw.domainsMux.RUnlock()
	assert.False(t, exists)
}

func TestProtect_UnknownDomainPassesThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://unknown.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend", rec.Body.String())
}

func TestProtect_DomainWithNoSchemesPassesThrough(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
	require.NoError(t, mw.AddDomain("example.com", nil, "", time.Hour, "", ""))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend", rec.Body.String())
}

func TestProtect_UnauthenticatedRequestIsBlocked(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	token, err := sessionkey.SignToken(kp.PrivateKey, "test-user", "example.com", auth.MethodPIN, time.Hour)
	require.NoError(t, err)

	capturedData := &proxy.CapturedData{}
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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp1 := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp1.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, auth.SessionCookieName, c.Name, "no session cookie should be set on failed auth")
	}
}

func TestProtect_MultipleSchemes(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
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
	require.NoError(t, mw.AddDomain("example.com", []Scheme{pinScheme, passwordScheme}, kp.PublicKey, time.Hour, "", ""))

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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	// Return a garbage token that won't validate.
	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "invalid-jwt-token", "", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	handler := mw.Protect(newPassthroughHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAddDomain_RandomBytes32NotEd25519(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)

	// 32 random bytes that happen to be valid base64 and correct size
	// but are actually a valid ed25519 public key length-wise.
	// This should succeed because ed25519 public keys are just 32 bytes.
	randomBytes := make([]byte, ed25519.PublicKeySize)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)

	key := base64.StdEncoding.EncodeToString(randomBytes)
	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}

	err = mw.AddDomain("example.com", []Scheme{scheme}, key, time.Hour, "", "")
	require.NoError(t, err, "any 32-byte key should be accepted at registration time")
}

func TestAddDomain_InvalidKeyDoesNotCorruptExistingConfig(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{method: auth.MethodPIN, promptID: "pin"}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	// Attempt to overwrite with an invalid key.
	err := mw.AddDomain("example.com", []Scheme{scheme}, "bad", time.Hour, "", "")
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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	// Scheme that always fails authentication (returns empty token)
	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	capturedData := &proxy.CapturedData{}
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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPassword,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "password", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	capturedData := &proxy.CapturedData{}
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
	mw := NewMiddleware(log.StandardLogger(), nil)
	kp := generateTestKeyPair(t)

	scheme := &stubScheme{
		method: auth.MethodPIN,
		authFn: func(_ *http.Request) (string, string, error) {
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain("example.com", []Scheme{scheme}, kp.PublicKey, time.Hour, "", ""))

	capturedData := &proxy.CapturedData{}
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
