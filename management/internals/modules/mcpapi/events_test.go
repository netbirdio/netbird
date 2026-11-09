package mcpapi

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/management/server/activity"
)

// userEvent is an event the stub user of newBrokerEnv caused on their own session.
func userEvent(code activity.Activity, meta map[string]any) storedEvent {
	return storedEvent{activity: code, initiator: "user-1", target: "user-1", account: "account-1", meta: meta}
}

func TestBrokerRecordsSignIns(t *testing.T) {
	t.Run("only the redemption that starts the session is recorded", func(t *testing.T) {
		env := newBrokerEnv(t)
		req := env.newRequest(env.register(clientCallback))
		code := env.login(req, true).Query().Get("code")

		// Redemptions refused before the session starts leave no trace.
		wrongVerifier := req
		wrongVerifier.verifier = oauth2.GenerateVerifier()
		status, _ := env.exchange(wrongVerifier, code)
		require.Equal(t, http.StatusBadRequest, status)
		otherClient := req
		otherClient.clientID = env.register(clientCallback)
		status, _ = env.exchange(otherClient, code)
		require.Equal(t, http.StatusBadRequest, status)
		faults := withFaults(env)
		faults.down.Store(true)
		status, _ = env.exchange(req, code)
		require.Equal(t, http.StatusServiceUnavailable, status)
		faults.down.Store(false)
		assert.Empty(t, env.accounts.takeEvents(), "a refused redemption records nothing")

		status, tokens := env.exchange(req, code)
		require.Equal(t, http.StatusOK, status, tokens)
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedIn, map[string]any{
			"client_name": "Test <Client>", "redirect_host": "localhost:3118", "access": "read and write",
		})}, env.accounts.takeEvents(), "the sign-in names the client, where the code went and the access granted")

		status, refreshed := env.tokenRequest(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {req.clientID},
		})
		require.Equal(t, http.StatusOK, status, refreshed)
		assert.Empty(t, env.accounts.takeEvents(), "a refresh continues the session and is not a sign-in")
	})

	t.Run("read-only access is recorded as read", func(t *testing.T) {
		env := newBrokerEnv(t)
		req := env.newRequest(env.register(clientCallback))
		status, tokens := env.exchange(req, env.login(req, false).Query().Get("code"))
		require.Equal(t, http.StatusOK, status, tokens)
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedIn, map[string]any{
			"client_name": "Test <Client>", "redirect_host": "localhost:3118", "access": "read",
		})}, env.accounts.takeEvents())
	})

	t.Run("a client's name is stored without control or hidden characters", func(t *testing.T) {
		env := newBrokerEnv(t)
		signInAs := func(name string) []storedEvent {
			status, reg := env.registerClient(map[string]any{"client_name": name, "redirect_uris": []string{clientCallback}})
			require.Equal(t, http.StatusCreated, status)
			req := env.newRequest(reg.ClientID)
			status, tokens := env.exchange(req, env.login(req, false).Query().Get("code"))
			require.Equal(t, http.StatusOK, status, tokens)
			return env.accounts.takeEvents()
		}

		// A right-to-left override (U+202E) shows "Editor", the override and "exe.txt" as
		// "Editortxt.exe" in a viewer that honors it, and zero-width spaces and newlines hide.
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedIn, map[string]any{
			"client_name": "Editorexe.txt Code", "redirect_host": "localhost:3118", "access": "read",
		})}, signInAs("\u200bEditor\u202Eexe.txt\u202C Code\n"), "only the visible characters remain")
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedIn, map[string]any{
			"redirect_host": "localhost:3118", "access": "read",
		})}, signInAs("\u202E\u200b\t"), "a name with nothing visible is left out")

		// Each input below is only cleaned by one branch: an inner control character, inner
		// line and paragraph separators (U+2028, U+2029), spaces left at the ends once the
		// hidden characters around them are gone, and a variation selector (U+E0100).
		for input, want := range map[string]string{
			"Edit\u0007or":         "Editor",
			"Ed\u2028it\u2029or":   "Editor",
			"\u200b Editor \u202E": "Editor",
			"Edit\U000E0100or":     "Editor",
		} {
			assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedIn, map[string]any{
				"client_name": want, "redirect_host": "localhost:3118", "access": "read",
			})}, signInAs(input), "client name %q", input)
		}

		// Hangul fillers (U+3164), the combining grapheme joiner (U+034F), a variation
		// selector (U+FE0F) and an unassigned tag (U+E0000) all render as nothing.
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedIn, map[string]any{
			"redirect_host": "localhost:3118", "access": "read",
		})}, signInAs("\u3164\u034f\ufe0f\U000E0000"), "default-ignorable characters are left out")
	})
}

func TestBrokerRecordsSignOuts(t *testing.T) {
	env := newBrokerEnv(t)

	t.Run("a revocation records the session's end once", func(t *testing.T) {
		s := env.signIn()
		env.accounts.takeEvents()

		require.Equal(t, http.StatusOK, env.revokeToken(s.refresh, s.req.clientID))
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedOut, map[string]any{
			"client_name": "Test <Client>", "access": "read and write",
		})}, env.accounts.takeEvents(), "the sign-out names the client that sent its client_id")

		require.Equal(t, http.StatusOK, env.revokeToken(s.access, s.req.clientID))
		assert.Empty(t, env.accounts.takeEvents(), "revoking the session's other token ends nothing more")
	})

	t.Run("a revocation without a client_id records no client name", func(t *testing.T) {
		s := env.signIn()
		env.accounts.takeEvents()

		require.Equal(t, http.StatusOK, env.revokeToken(s.access, ""))
		assert.Equal(t, []storedEvent{userEvent(activity.MCPClientSignedOut, map[string]any{"access": "read and write"})},
			env.accounts.takeEvents())
	})

	t.Run("a refused or empty revocation records nothing", func(t *testing.T) {
		s := env.signIn()
		env.accounts.takeEvents()

		assert.Equal(t, http.StatusBadRequest, env.revokeToken(s.refresh, env.register(clientCallback)), "another client's token")
		assert.Equal(t, http.StatusOK, env.revokeToken("nbmcpr_garbage", s.req.clientID), "a token the broker never issued")
		faults := withFaults(env)
		faults.down.Store(true)
		assert.Equal(t, http.StatusServiceUnavailable, env.revokeToken(s.refresh, s.req.clientID), "a store outage")
		faults.down.Store(false)
		assert.Empty(t, env.accounts.takeEvents())
		assert.Equal(t, http.StatusOK, env.callMCP("/api/mcp", s.access, nil).status, "the session is untouched")
	})
}

func TestBrokerRecordsTokenReuse(t *testing.T) {
	t.Run("a replayed refresh token", func(t *testing.T) {
		env := newBrokerEnv(t)
		s := env.signIn()
		status, out := env.refreshWith(s, s.refresh)
		require.Equal(t, http.StatusOK, status, out)
		env.accounts.takeEvents()

		env.now = env.now.Add(refreshGrace + time.Second)
		status, out = env.refreshWith(s, s.refresh)
		require.Equal(t, http.StatusBadRequest, status, out)
		assert.Equal(t, []storedEvent{userEvent(activity.MCPSessionRevokedOnTokenReuse, map[string]any{
			"client_name": "Test <Client>", "access": "read and write",
		})}, env.accounts.takeEvents(), "the replay that revoked the session is recorded")
	})

	t.Run("an authorization code redeemed twice", func(t *testing.T) {
		env := newBrokerEnv(t)
		req := env.newRequest(env.register(clientCallback))
		code := env.login(req, false).Query().Get("code")
		status, tokens := env.exchange(req, code)
		require.Equal(t, http.StatusOK, status, tokens)
		env.accounts.takeEvents()

		status, out := env.exchange(req, code)
		require.Equal(t, http.StatusBadRequest, status, out)
		assert.Equal(t, []storedEvent{userEvent(activity.MCPSessionRevokedOnTokenReuse, map[string]any{
			"client_name": "Test <Client>", "redirect_host": "localhost:3118", "access": "read",
		})}, env.accounts.takeEvents(), "the second redemption is recorded with what the code carried")

		status, out = env.exchange(req, code)
		require.Equal(t, http.StatusBadRequest, status, out)
		assert.Empty(t, env.accounts.takeEvents(), "later redemptions find no session to revoke and record nothing")
	})
}
