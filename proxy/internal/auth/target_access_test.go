package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proxyauth "github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
)

type targetAccessRoundTripFunc func(*http.Request) (*http.Response, error)

func (f targetAccessRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func targetAccessResolver(t *testing.T, action proxy.AccessAction) *proxy.TargetResolver {
	t.Helper()
	targetURL, err := url.Parse("http://backend.internal")
	require.NoError(t, err)
	resolver, err := proxy.NewTargetResolver(proxy.Mapping{
		ID:        "service-1",
		AccountID: "account-1",
		Host:      "example.com",
		Paths: map[string]*proxy.PathTarget{
			"/selected": {
				URL:          targetURL,
				AccessAction: action,
			},
		},
	})
	require.NoError(t, err)
	return resolver
}

func TestProtect_TargetAccessActions(t *testing.T) {
	tests := []struct {
		name             string
		action           proxy.AccessAction
		wantStatus       int
		wantBackendCalls int
		wantSchemeCalls  int
		wantCacheControl string
	}{
		{
			name:             "bypass forwards without authentication",
			action:           proxy.AccessActionBypass,
			wantStatus:       http.StatusNoContent,
			wantBackendCalls: 1,
		},
		{
			name:             "block rejects before authentication",
			action:           proxy.AccessActionBlock,
			wantStatus:       http.StatusForbidden,
			wantSchemeCalls:  0,
			wantCacheControl: "no-store",
		},
		{
			name:            "inherit runs configured authentication",
			action:          proxy.AccessActionInherit,
			wantStatus:      http.StatusUnauthorized,
			wantSchemeCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewMiddleware(log.StandardLogger(), nil, nil)
			kp := generateTestKeyPair(t)
			schemeCalls := 0
			scheme := &stubScheme{
				method: proxyauth.MethodPIN,
				authFn: func(*http.Request) (string, string, error) {
					schemeCalls++
					return "", "pin", nil
				},
			}
			err := mw.AddDomain(
				"example.com",
				[]Scheme{scheme},
				kp.PublicKey,
				time.Hour,
				"account-1",
				"service-1",
				nil,
				false,
				nil,
				WithTargetResolver(targetAccessResolver(t, tt.action)),
			)
			require.NoError(t, err)

			backendCalls := 0
			handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				backendCalls++
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodGet, "http://example.com/selected/status", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, tt.wantBackendCalls, backendCalls, "backend call count")
			assert.Equal(t, tt.wantSchemeCalls, schemeCalls, "authentication scheme call count")
			assert.Equal(t, tt.wantCacheControl, rec.Header().Get("Cache-Control"), "cache policy")
		})
	}
}

func TestProtect_BypassRecordsActionWithoutIdentity(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain(
		"example.com", nil, "", 0, "account-1", "service-1", nil, false, nil,
		WithTargetResolver(targetAccessResolver(t, proxy.AccessActionBypass)),
	))

	handler := mw.Protect(newPassthroughHandler())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/selected", nil)
	captured := proxy.NewCapturedData("request-1")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), captured))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, captured.GetUserID())
	assert.Empty(t, captured.GetUserEmail())
	assert.Empty(t, captured.GetUserGroups())
	assert.Equal(t, "path_bypass", captured.GetAuthMethod())
	assert.Equal(t, "bypass", captured.GetMetadata()["access_action"])
}

func TestProtect_TargetResolverPinsMissThroughAuthentication(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	resolver := targetAccessResolver(t, proxy.AccessActionBypass)
	require.NoError(t, mw.AddDomain(
		"example.com", nil, "", 0, "account-1", "service-1", nil, false, nil,
		WithTargetResolver(resolver),
	))

	forwarded := false
	reverseProxy := proxy.NewReverseProxy(targetAccessRoundTripFunc(func(*http.Request) (*http.Response, error) {
		forwarded = true
		return nil, errors.New("unexpected forwarding")
	}), "auto", nil, nil)
	replacementURL, err := url.Parse("http://replacement.internal")
	require.NoError(t, err)
	reverseProxy.AddMapping(proxy.Mapping{
		ID:        "service-1",
		AccountID: "account-1",
		Host:      "example.com",
		Paths: map[string]*proxy.PathTarget{
			"/": {URL: replacementURL},
		},
	})
	handler := mw.Protect(reverseProxy)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/not-selected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "a miss pinned before auth must reach the proxy unchanged")
	assert.False(t, forwarded, "the proxy must not fall back to a newly published mapping after a pinned miss")
}

func TestProtect_UnsafePathFailsBeforeAuthentication(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	schemeCalls := 0
	scheme := &stubScheme{
		method: proxyauth.MethodPIN,
		authFn: func(*http.Request) (string, string, error) {
			schemeCalls++
			return "", "pin", nil
		},
	}
	require.NoError(t, mw.AddDomain(
		"example.com",
		[]Scheme{scheme},
		kp.PublicKey,
		time.Hour,
		"account-1",
		"service-1",
		nil,
		false,
		nil,
		WithTargetResolver(targetAccessResolver(t, proxy.AccessActionBlock)),
	))

	backendCalled := false
	handler := mw.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		backendCalled = true
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.URL.Path = "/selected/../other"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Zero(t, schemeCalls, "unsafe paths must be rejected before credentials are evaluated")
	assert.False(t, backendCalled)
}

func TestProtect_IPRestrictionsRunBeforeTargetAccessAction(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain(
		"example.com", nil, "", 0, "account-1", "service-1", filter, false, nil,
		WithTargetResolver(targetAccessResolver(t, proxy.AccessActionBypass)),
	))

	backendCalled := false
	handler := mw.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		backendCalled = true
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/selected", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, backendCalled, "bypass must not bypass service IP restrictions")
}

func TestNewDomainConfig_RejectsPrivateBypass(t *testing.T) {
	_, err := NewDomainConfig(
		"private.example.com",
		nil,
		"",
		0,
		"account-1",
		"service-1",
		nil,
		true,
		nil,
		WithTargetResolver(targetAccessResolver(t, proxy.AccessActionBypass)),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed for private domain")
}

func TestAddDomainConfig_PublishesPreparedSnapshot(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	config, err := NewDomainConfig(
		"example.com",
		nil,
		"",
		0,
		"account-1",
		"service-1",
		nil,
		false,
		[]string{"group-1"},
		WithTargetResolver(targetAccessResolver(t, proxy.AccessActionBlock)),
	)
	require.NoError(t, err)

	mw.AddDomainConfig("example.com", config)
	delete(config.AllowedGroups, "group-1")

	published, exists := mw.getDomainConfig("example.com")
	require.True(t, exists)
	assert.Contains(t, published.AllowedGroups, "group-1", "published mutable fields should be copied")
	assert.NotNil(t, published.TargetResolver)
}
