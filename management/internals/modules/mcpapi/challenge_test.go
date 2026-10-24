package mcpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// challengeRouter mounts the MCP path and a neighbour behind the challenge middleware and a
// stand-in auth middleware that refuses every request lacking a token.
func challengeRouter() *mux.Router {
	root := mux.NewRouter()
	root.Use((&Broker{}).ChallengeMiddleware())
	root.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"no valid authentication provided","code":401}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	root.HandleFunc(apiPrefix+Path, ok)
	root.HandleFunc(apiPrefix+"/peers", ok)
	return root
}

func TestChallengeMiddlewareAddsPointerOnUnauthorizedMCPCall(t *testing.T) {
	router := challengeRouter()

	req := httptest.NewRequest(http.MethodPost, "http://mgmt.example.com/api/mcp", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer resource_metadata="https://mgmt.example.com/api/mcp/.well-known/oauth-protected-resource"`, rec.Header().Get("WWW-Authenticate"))
	assert.Contains(t, rec.Body.String(), "no valid authentication provided", "the API's own error body is preserved")
}

func TestChallengeMiddlewareLeavesOtherResponsesAlone(t *testing.T) {
	router := challengeRouter()

	req := httptest.NewRequest(http.MethodPost, "http://mgmt.example.com/api/mcp", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"), "a successful call carries no challenge")
	assert.Equal(t, "ok", rec.Body.String())

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://mgmt.example.com/api/peers", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"), "only the MCP endpoint advertises resource metadata")
}

func TestChallengeWriterKeepsFlushing(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &challengeWriter{ResponseWriter: rec, metadataURL: "https://mgmt.example.com/x"}
	_, err := w.Write([]byte("data"))
	require.NoError(t, err)
	w.Flush()
	assert.True(t, rec.Flushed, "flushes reach the underlying writer")
	assert.Equal(t, http.StatusOK, rec.Code, "an implicit write means 200")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"))
}
