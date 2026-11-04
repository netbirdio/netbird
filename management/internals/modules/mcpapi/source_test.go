package mcpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/formatter/hook"
)

// TestBrokerRequestsLogAsMCP checks that the broker's endpoints and its access token check
// mark their requests as MCP, so what they log reads context=MCP rather than HTTP.
func TestBrokerRequestsLogAsMCP(t *testing.T) {
	logger := log.StandardLogger()
	level := logger.GetLevel()
	hooks := logger.ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() {
		logger.SetLevel(level)
		logger.ReplaceHooks(hooks)
	})
	logger.SetLevel(log.DebugLevel)
	logs := logtest.NewLocal(logger)

	env := newBrokerEnv(t)
	s := env.signIn()
	status, out := env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusOK, status, out)
	// Replaying the replaced refresh token after the grace period revokes the session, which
	// the token endpoint logs with the request context.
	env.now = env.now.Add(refreshGrace + time.Second)
	status, out = env.refreshWith(s, s.refresh)
	require.Equal(t, http.StatusBadRequest, status, out)

	// A broker token that does not open is refused by the access token check on /api/mcp,
	// before the MCP handler runs.
	require.Equal(t, http.StatusUnauthorized, env.callMCP("/api/mcp", accessTokenPrefix+"not-a-token", nil).status)

	assert.Equal(t, hook.MCPSource, sourceOf(t, logs, "MCP refresh token reused"), "the token endpoint logs as MCP")
	assert.Equal(t, hook.MCPSource, sourceOf(t, logs, "MCP access token rejected"), "the access token check logs as MCP")
}

// TestAuthMiddlewareMarksOnlyTheMCPEndpoint checks that a PAT or dashboard login on the MCP
// endpoint reaches the API auth already marked as MCP, and other API paths stay unmarked.
func TestAuthMiddlewareMarksOnlyTheMCPEndpoint(t *testing.T) {
	env := newBrokerEnv(t)
	var seen any
	apiAuth := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Context().Value(hook.ExecutionContextKey)
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	handler := env.broker.AuthMiddleware(apiAuth)(http.NotFoundHandler())
	for path, want := range map[string]any{apiPrefix + Path: hook.MCPSource, apiPrefix + "/peers": nil} {
		seen = "not reached"
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Token nbp_example")
		handler.ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, want, seen, "source the API auth sees on %s", path)
	}
}

// sourceOf returns the execution context of the first log entry whose message starts with prefix.
func sourceOf(t *testing.T, logs *logtest.Hook, prefix string) any {
	t.Helper()
	for _, entry := range logs.AllEntries() {
		if strings.HasPrefix(entry.Message, prefix) {
			require.NotNil(t, entry.Context, "%q is logged with the request context", prefix)
			return entry.Context.Value(hook.ExecutionContextKey)
		}
	}
	require.Failf(t, "log line not found", "no log entry starts with %q", prefix)
	return nil
}
