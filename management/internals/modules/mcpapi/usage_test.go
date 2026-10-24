package mcpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestUsageCountsTheLastDay(t *testing.T) {
	u := NewUsage()
	start := time.Date(2026, 10, 24, 9, 30, 0, 0, time.UTC)

	u.record("user-1", start)
	u.record("user-1", start.Add(time.Minute))
	u.record("user-2", start.Add(5*time.Hour))
	calls, users := u.LastDay(start.Add(5 * time.Hour))
	assert.Equal(t, 3, calls, "calls in the last day")
	assert.Equal(t, 2, users, "a user who called twice counts once")

	calls, users = u.LastDay(start.Add(24 * time.Hour))
	assert.Equal(t, 1, calls, "the first hour has left the window")
	assert.Equal(t, 1, users)

	// The bucket of the first hour is reused a day later and starts empty.
	u.record("user-3", start.Add(24*time.Hour))
	calls, users = u.LastDay(start.Add(24 * time.Hour))
	assert.Equal(t, 2, calls)
	assert.Equal(t, 2, users)

	calls, users = u.LastDay(start.Add(48 * time.Hour))
	assert.Zero(t, calls, "nothing older than a day is reported")
	assert.Zero(t, users)
}

func TestUsageNilCountsNothing(t *testing.T) {
	var u *Usage
	u.record("user-1", time.Now())
	calls, users := u.LastDay(time.Now())
	assert.Zero(t, calls)
	assert.Zero(t, users)
}

func TestToolCallsAreCounted(t *testing.T) {
	usage := NewUsage()
	root := mux.NewRouter()
	root.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "acc-1", UserId: "user-1"}))
		})
	})
	require.NoError(t, RegisterEndpoints(root.PathPrefix("/api").Subrouter(), echoRouter(t), Options{Tools: []string{"list_peers"}, Usage: usage}))
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)

	call := func(body string) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api"+Path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_peers","arguments":{}}}`)
	call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_guide","arguments":{"topic":"exit-nodes"}}}`)

	calls, users := usage.LastDay(time.Now())
	assert.Equal(t, 2, calls, "tool calls count, listing tools does not")
	assert.Equal(t, 1, users)
}

// A reverse proxy on the same host connects over loopback and forwards the public Host.
func TestEndpointAcceptsAPublicHostOverLoopback(t *testing.T) {
	root := mux.NewRouter()
	root.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "acc-1", UserId: "user-1"}))
		})
	})
	require.NoError(t, RegisterEndpoints(root.PathPrefix("/api").Subrouter(), echoRouter(t), Options{Tools: []string{"list_peers"}}))
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/api"+Path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.NoError(t, err)
	req.Host = "netbird.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the endpoint answers a proxied request on the loopback listener")
}
