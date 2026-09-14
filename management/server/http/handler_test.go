package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCORSExposesETag pins the reason this policy is spelled out instead of
// being cors.AllowAll(). ETag is not a CORS-safelisted response header, so
// without it named in Access-Control-Expose-Headers a browser client is handed
// a validator it cannot read — conditional requests would work for the CLI,
// the REST client and Terraform, and silently not for the dashboard.
//
// Collapsing this back to cors.AllowAll() is exactly the simplification that
// would reintroduce that, which is what this test is here to catch.
func TestCORSExposesETag(t *testing.T) {
	handler := newCORSMiddleware().Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"9f86d081884c7d65"`)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/agent-network/settings", nil)
	req.Header.Set("Origin", "https://app.netbird.io")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Compared canonicalized: the library normalizes the name it echoes, so
	// this reads "Etag" rather than "ETag". Browsers match the exposed-header
	// list case-insensitively, so the spelling does not matter — but asserting
	// it byte-exactly would fail for a reason that has nothing to do with the
	// behaviour being pinned.
	assert.Equal(t, http.CanonicalHeaderKey("ETag"),
		http.CanonicalHeaderKey(rec.Header().Get("Access-Control-Expose-Headers")),
		"browser clients must be allowed to read the validator they are sent")
}

// TestCORSAllowsIfMatchPreflight covers the request half. It needs nothing
// beyond the wildcard AllowedHeaders that was already there, so this is a
// regression guard rather than a new grant: narrowing AllowedHeaders to a list
// later must not drop If-Match and leave writes readable but not conditional.
func TestCORSAllowsIfMatchPreflight(t *testing.T) {
	handler := newCORSMiddleware().Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/agent-network/settings", nil)
	req.Header.Set("Origin", "https://app.netbird.io")
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	req.Header.Set("Access-Control-Request-Headers", "If-Match")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "If-Match",
		"a conditional write must survive preflight")
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodPut,
		"the conditional write's method must survive preflight")
}

// TestCORSMatchesAllowAllOtherwise pins the rest of the policy, which is a
// verbatim copy of cors.AllowAll(). Spelling the options out is what let ETag
// be added; it also means a change to the library's defaults no longer reaches
// this API, so the settings that matter are asserted here rather than assumed.
func TestCORSMatchesAllowAllOtherwise(t *testing.T) {
	handler := newCORSMiddleware().Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/peers", nil)
	req.Header.Set("Origin", "https://anywhere.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodDelete)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"), "any origin must still be allowed")
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"),
		"credentials must stay disallowed — allowing them alongside a wildcard origin would be a real weakening")
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodDelete,
		"the full method set must still be allowed")
}
