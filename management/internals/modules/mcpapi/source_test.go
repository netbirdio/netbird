package mcpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/formatter/hook"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/auth"
)

// TestBrokerRequestsLogAsMCP checks that the broker's endpoints and its access token check
// mark their requests as MCP, so what they log reads context=MCP rather than HTTP.
func TestBrokerRequestsLogAsMCP(t *testing.T) {
	logs := captureLogs(t)

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

	// Discovery is served from the root router rather than the API one.
	env.getJSON(ProtectedResourcePath, nil, &map[string]any{})

	assert.Equal(t, hook.MCPSource, sourceOf(t, logs, "MCP refresh token reused"), "the token endpoint logs as MCP")
	assert.Equal(t, hook.MCPSource, sourceOf(t, logs, "MCP access token rejected"), "the access token check logs as MCP")
	// The HTTP metrics middleware logs each response after the handlers return, from the
	// request they marked.
	for _, path := range []string{"POST " + apiPrefix + tokenPath, "POST " + apiPrefix + Path, "GET " + ProtectedResourcePath} {
		assert.Equal(t, hook.MCPSource, sourceOf(t, logs, "request "+path+" took"), "the metrics log of %s reads MCP", path)
	}
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

// TestMetricsLogKeepsTheMCPCaller checks that the HTTP metrics middleware, which logs every
// response after the handlers return, sees both the MCP mark and the caller, whichever
// credential signed in. The API auth and the broker hand the caller back by overwriting the
// request they were given, so nothing between them and the metrics middleware may copy it.
func TestMetricsLogKeepsTheMCPCaller(t *testing.T) {
	logs := captureLogs(t)
	env := newBrokerEnv(t)

	t.Run("PAT", func(t *testing.T) {
		logs.Reset()
		metrics, err := telemetry.NewMetricsMiddleware(context.Background(), noop.NewMeterProvider().Meter(""))
		require.NoError(t, err)
		// Stands in for the API auth accepting a PAT, updating the request in place as it does.
		apiAuth := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				*r = *nbcontext.SetUserAuthInRequest(r, auth.UserAuth{UserId: "user-1", AccountId: "account-1", IsPAT: true})
				next.ServeHTTP(w, r)
			})
		}
		handler := metrics.Handler(env.broker.AuthMiddleware(apiAuth)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

		for path, want := range map[string]hook.ExecutionContext{apiPrefix + Path: hook.MCPSource, apiPrefix + "/peers": hook.HTTPSource} {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Authorization", "Token nbp_example")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "status on %s", path)
			assertMetricsCaller(t, entryOf(t, logs, "request POST "+path+" took"), want)
		}
	})

	t.Run("broker token", func(t *testing.T) {
		s := env.signIn()
		logs.Reset()
		require.Equal(t, http.StatusOK, env.callMCP(apiPrefix+Path, s.access, nil).status)
		assertMetricsCaller(t, entryOf(t, logs, "request POST "+apiPrefix+Path+" took"), hook.MCPSource)
	})
}

// assertMetricsCaller checks the source and the caller a metrics log line carries.
func assertMetricsCaller(t *testing.T, entry log.Entry, source hook.ExecutionContext) {
	t.Helper()
	assert.Equal(t, source, entry.Data["context"], "source the metrics log reads for %q", entry.Message)
	assert.Equal(t, "user-1", entry.Data[nbcontext.UserIDKey], "user the metrics log reads for %q", entry.Message)
	assert.Equal(t, "account-1", entry.Data[nbcontext.AccountIDKey], "account the metrics log reads for %q", entry.Message)
}

// captureLogs records what the standard logger writes at debug level, with the production
// context hook installed so entries carry the fields it adds.
func captureLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	logger := log.StandardLogger()
	level := logger.GetLevel()
	hooks := logger.ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() {
		logger.SetLevel(level)
		logger.ReplaceHooks(hooks)
	})
	logger.SetLevel(log.DebugLevel)
	logger.AddHook(hook.NewContextHook())
	return logtest.NewLocal(logger)
}

// entryOf returns the first log entry whose message starts with prefix.
func entryOf(t *testing.T, logs *logtest.Hook, prefix string) log.Entry {
	t.Helper()
	for _, entry := range logs.AllEntries() {
		if strings.HasPrefix(entry.Message, prefix) {
			return *entry
		}
	}
	require.Failf(t, "log line not found", "no log entry starts with %q", prefix)
	return log.Entry{}
}

// sourceOf returns the context field the log hook added to the first entry whose message
// starts with prefix.
func sourceOf(t *testing.T, logs *logtest.Hook, prefix string) any {
	t.Helper()
	return entryOf(t, logs, prefix).Data["context"]
}
