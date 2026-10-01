package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

type resolverRoundTripFunc func(*http.Request) (*http.Response, error)

func (f resolverRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func resolverMapping(targets map[string]*PathTarget) Mapping {
	return Mapping{
		ID:        "service-1",
		AccountID: "account-1",
		Host:      "example.com",
		Paths:     targets,
	}
}

func mustTargetURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	targetURL, err := url.Parse(rawURL)
	require.NoError(t, err)
	return targetURL
}

func TestTargetResolver_LongestPrefixPinsTargetAndAction(t *testing.T) {
	mapping := resolverMapping(map[string]*PathTarget{
		"/": {
			URL:          mustTargetURL(t, "http://root.internal"),
			AccessAction: AccessActionInherit,
		},
		"/public": {
			URL:           mustTargetURL(t, "http://public.internal"),
			AccessAction:  AccessActionBypass,
			CustomHeaders: map[string]string{"X-Target": "original"},
		},
	})
	resolver, err := NewTargetResolver(mapping)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/public/status", nil)
	resolvedReq, action, err := resolver.ResolveRequest(req)
	require.NoError(t, err)
	assert.Equal(t, AccessActionBypass, action, "the longest matching target action should be selected")

	// Mutating both the source mapping and the live proxy mapping must not
	// change the target already selected by the auth snapshot.
	mapping.Paths["/public"].URL.Host = "mutated.internal"
	mapping.Paths["/public"].CustomHeaders["X-Target"] = "mutated"
	liveMapping := resolverMapping(map[string]*PathTarget{
		"/": {URL: mustTargetURL(t, "http://replacement.internal")},
	})

	var gotHost, gotHeader string
	rp := NewReverseProxy(resolverRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotHost = req.URL.Host
		gotHeader = req.Header.Get("X-Target")
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	}), "auto", nil, nil)
	rp.AddMapping(liveMapping)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, resolvedReq)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "public.internal", gotHost, "forwarding must reuse the target pinned before auth")
	assert.Equal(t, "original", gotHeader, "resolver-owned target options must be immutable")
}

func TestTargetResolver_PinnedMissDoesNotFallBackToNewMapping(t *testing.T) {
	resolver, err := NewTargetResolver(resolverMapping(map[string]*PathTarget{
		"/api": {URL: mustTargetURL(t, "http://api.internal")},
	}))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	resolvedReq, action, err := resolver.ResolveRequest(req)
	require.NoError(t, err)
	assert.Equal(t, AccessActionInherit, action)

	called := false
	rp := NewReverseProxy(resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected forwarding")
	}), "auto", nil, nil)
	rp.AddMapping(resolverMapping(map[string]*PathTarget{
		"/": {URL: mustTargetURL(t, "http://new.internal")},
	}))
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, resolvedReq)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.False(t, called, "a miss pinned before auth must not be resolved again after an update")
}

func TestReverseProxy_UnpinnedNonDefaultMappingFailsClosed(t *testing.T) {
	called := false
	rp := NewReverseProxy(resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected forwarding")
	}), "auto", nil, nil)
	rp.AddMapping(resolverMapping(map[string]*PathTarget{
		"/": {
			URL:          mustTargetURL(t, "http://public.internal"),
			AccessAction: AccessActionBypass,
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.False(t, called, "a target access action must never forward without an auth-owned resolution")
}

func TestReverseProxy_ConfiguredMiddlewareMissingChainFailsClosed(t *testing.T) {
	called := false
	manager := middleware.NewManager(0, nil, nil)
	rp := NewReverseProxy(resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected forwarding")
	}), "auto", nil, nil, WithMiddlewareManager(manager))
	rp.AddMapping(resolverMapping(map[string]*PathTarget{
		"/": {
			URL: mustTargetURL(t, "http://protected.internal"),
			Middlewares: []middleware.Spec{{
				ID:      "required-policy",
				Slot:    middleware.SlotOnRequest,
				Enabled: true,
			}},
		},
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.False(t, called, "a missing configured policy chain must never become pass-through")
}

func TestReverseProxy_PinnedTargetFailsClosedAfterMiddlewareRemoval(t *testing.T) {
	target := &PathTarget{
		URL:          mustTargetURL(t, "http://protected.internal"),
		AccessAction: AccessActionInherit,
		Middlewares: []middleware.Spec{{
			ID:      "required-policy",
			Slot:    middleware.SlotOnRequest,
			Enabled: true,
		}},
	}
	mapping := resolverMapping(map[string]*PathTarget{"/": target})
	resolver, err := NewTargetResolver(mapping)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resolvedReq, _, err := resolver.ResolveRequest(req)
	require.NoError(t, err)

	called := false
	manager := middleware.NewManager(0, nil, nil)
	manager.Invalidate(string(mapping.ID))
	rp := NewReverseProxy(resolverRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected forwarding")
	}), "auto", nil, nil, WithMiddlewareManager(manager))
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, resolvedReq)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, called, "a stale pinned target must not bypass a removed policy chain")
}

func TestTargetResolver_RejectsUnsafePathsWhenActionsAreConfigured(t *testing.T) {
	resolver, err := NewTargetResolver(resolverMapping(map[string]*PathTarget{
		"/public": {
			URL:          mustTargetURL(t, "http://public.internal"),
			AccessAction: AccessActionBypass,
		},
		"/": {URL: mustTargetURL(t, "http://root.internal")},
	}))
	require.NoError(t, err)

	tests := []struct {
		name    string
		path    string
		rawPath string
	}{
		{name: "dot segment", path: "/public/../private"},
		{name: "duplicate separator", path: "/public//private"},
		{name: "backslash", path: `/public\private`},
		{name: "path parameter", path: "/public;ignored/private"},
		{name: "encoded query delimiter", path: "/public?ignored", rawPath: "/public%3fignored"},
		{name: "encoded fragment delimiter", path: "/public#ignored", rawPath: "/public%23ignored"},
		{name: "encoded slash", path: "/public/private", rawPath: "/public%2fprivate"},
		{name: "encoded dot", path: "/public/../private", rawPath: "/public/%2e%2e/private"},
		{name: "double encoding", path: "/public/%2e%2e/private", rawPath: "/public/%252e%252e/private"},
		{name: "escaped NUL", path: "/public/\x00private", rawPath: "/public/%00private"},
		{name: "mismatched raw path", path: "/public/safe", rawPath: "/different"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.URL.Path = tt.path
			req.URL.RawPath = tt.rawPath

			_, _, err := resolver.ResolveRequest(req)

			require.ErrorIs(t, err, ErrUnsafeRequestPath)
		})
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/public/file%20name", nil)
	_, action, err := resolver.ResolveRequest(req)
	require.NoError(t, err)
	assert.Equal(t, AccessActionBypass, action, "ordinary percent-encoded path data should remain supported")
}

func TestTargetResolver_InheritOnlyPreservesLegacyPathHandling(t *testing.T) {
	resolver, err := NewTargetResolver(resolverMapping(map[string]*PathTarget{
		"/": {URL: mustTargetURL(t, "http://root.internal")},
	}))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.URL.Path = "/legacy/../path"
	resolvedReq, action, err := resolver.ResolveRequest(req)

	require.NoError(t, err)
	assert.Equal(t, AccessActionInherit, action)
	_, pinned := targetResolutionFromContext(resolvedReq.Context())
	assert.True(t, pinned, "inherit-only mappings should still pin their target snapshot")
}

func TestNewTargetResolver_RejectsInvalidAccessActions(t *testing.T) {
	tests := []struct {
		name   string
		target *PathTarget
	}{
		{
			name: "unknown action",
			target: &PathTarget{
				URL:          mustTargetURL(t, "http://target.internal"),
				AccessAction: AccessAction("unknown"),
			},
		},
		{
			name: "Agent Network bypass",
			target: &PathTarget{
				URL:          mustTargetURL(t, "http://target.internal"),
				AccessAction: AccessActionBypass,
				AgentNetwork: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTargetResolver(resolverMapping(map[string]*PathTarget{"/": tt.target}))
			require.Error(t, err)
		})
	}
}

func TestNewTargetResolver_RejectsNoncanonicalAccessPrefixes(t *testing.T) {
	prefixes := []string{
		"public",
		"/public/../private",
		"/public//nested",
		`/public\nested`,
		"/public;parameter",
		"/public%2fprivate",
		"/public?query",
		"/public#fragment",
		"/public\x00nested",
	}

	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			_, err := NewTargetResolver(resolverMapping(map[string]*PathTarget{
				prefix: {
					URL:          mustTargetURL(t, "http://target.internal"),
					AccessAction: AccessActionBlock,
				},
				"/": {URL: mustTargetURL(t, "http://root.internal")},
			}))

			require.ErrorIs(t, err, ErrUnsafeRequestPath)
		})
	}
}
