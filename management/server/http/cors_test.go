package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newCORSPreflight(origin string) *http.Request {
	r := httptest.NewRequest(http.MethodOptions, "/api/peers", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", http.MethodPut)
	r.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	return r
}

func serveCORS(t *testing.T, allowedOrigins []string, r *http.Request) http.Header {
	t.Helper()

	w := httptest.NewRecorder()
	CORSMiddleware(allowedOrigins).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	return w.Header()
}

func TestCORSMiddlewareAllowsConfiguredOrigin(t *testing.T) {
	headers := serveCORS(t, []string{"https://app.example.com"}, newCORSPreflight("https://app.example.com"))

	assert.Equal(t, "https://app.example.com", headers.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, headers.Get("Vary"), "Origin")
}

func TestCORSMiddlewareRejectsUnknownOrigin(t *testing.T) {
	headers := serveCORS(t, []string{"https://app.example.com"}, newCORSPreflight("https://evil.example.com"))

	assert.Empty(t, headers.Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareNeverAllowsCredentials(t *testing.T) {
	for _, allowedOrigins := range [][]string{nil, {"https://app.example.com"}} {
		headers := serveCORS(t, allowedOrigins, newCORSPreflight("https://app.example.com"))

		assert.Empty(t, headers.Get("Access-Control-Allow-Credentials"))
		assert.Empty(t, headers.Get("Access-Control-Expose-Headers"))
	}
}

func TestCORSMiddlewareWithoutConfigAllowsAnyOrigin(t *testing.T) {
	headers := serveCORS(t, nil, newCORSPreflight("https://evil.example.com"))

	assert.Equal(t, "*", headers.Get("Access-Control-Allow-Origin"))
}
