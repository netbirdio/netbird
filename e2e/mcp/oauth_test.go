//go:build e2e

package mcpe2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// The whole journey of a remote MCP client against a deployment that set nothing but
// NB_MCP_ENABLED: discovery from the 401, dynamic registration, consent, sign-in at the
// embedded Dex as the bootstrapped admin, the code exchange with PKCE, tool calls with
// the broker's token, refresh and revocation. Dex only accepts the broker's callback
// because the embedded IdP registers it on its own, so this passing is the proof that
// self-hosted deployments need no configuration change.
func TestOAuthThroughEmbeddedIdP(t *testing.T) {
	logsOnFailure(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	client := newOAuthClient(ctx, t)
	code, verifier := client.authorize(ctx, true)
	tokens := client.exchange(ctx, code, verifier)
	assert.Equal(t, "Bearer", tokens.TokenType, "token type")
	assert.ElementsMatch(t, []string{scopeRead, scopeWrite}, strings.Fields(tokens.Scope), "write was approved")
	assert.Positive(t, tokens.ExpiresIn, "the access token carries its lifetime")

	session := connect(ctx, t, client.resource, "Bearer "+tokens.AccessToken, client.browser.Transport)

	var me api.User
	decodeResult(t, "get_current_user", callTool(ctx, t, session, "get_current_user", nil), &me)
	assert.Equal(t, harness.AdminEmail, me.Email, "the token acts as the user who signed in at Dex")

	name := uniqueName("mcp-e2e-oauth")
	var created api.Group
	decodeResult(t, "create_group", callTool(ctx, t, session, "create_group", map[string]any{"name": name}), &created)
	require.NotEmpty(t, created.Id, "create_group returns the new group")
	t.Cleanup(func() { deleteGroupIfPresent(t, created.Id) })
	stored, err := srv.API().Groups.Get(ctx, created.Id)
	require.NoError(t, err, "the group created with the OAuth token must be readable over REST")
	assert.Equal(t, name, stored.Name, "REST must show the name sent over MCP")

	res := callTool(ctx, t, session, "delete_group", map[string]any{"group_id": created.Id})
	require.False(t, res.IsError, "delete_group failed: %s", resultText(t, res))
	assert.False(t, groupExists(ctx, t, created.Id), "the group deleted over MCP must be gone from REST")

	// The broker's tokens are bound to the MCP endpoint and must not open the REST API.
	assert.Equal(t, http.StatusUnauthorized,
		client.status(ctx, srv.PublicURL()+"/api/groups", "Bearer "+tokens.AccessToken),
		"a broker access token must be refused outside /api/mcp")

	status, body := client.tokenRequest(ctx, client.refreshForm(tokens.RefreshToken))
	require.Equal(t, http.StatusOK, status, "refresh: %s", body)
	refreshed := decodeTokens(t, body)
	assert.NotEqual(t, tokens.RefreshToken, refreshed.RefreshToken, "refreshing rotates the refresh token")
	assert.ElementsMatch(t, []string{scopeRead, scopeWrite}, strings.Fields(refreshed.Scope), "refresh keeps the approved scopes")
	status, _ = probe(ctx, t, client.browser, client.resource, "Bearer "+refreshed.AccessToken)
	assert.Equal(t, http.StatusOK, status, "the refreshed access token is accepted")

	client.revoke(ctx, refreshed.RefreshToken)
	for label, access := range map[string]string{"first": tokens.AccessToken, "refreshed": refreshed.AccessToken} {
		status, _ = probe(ctx, t, client.browser, client.resource, "Bearer "+access)
		assert.Equal(t, http.StatusUnauthorized, status, "revoking the session must end the %s access token", label)
	}
	status, body = client.tokenRequest(ctx, client.refreshForm(refreshed.RefreshToken))
	assert.Equal(t, http.StatusBadRequest, status, "a revoked refresh token must not refresh: %s", body)
	assert.Contains(t, body, "invalid_grant", "the error that makes clients sign in again")
}

// A user who leaves "Make changes" unticked gets a token that reads but cannot write,
// whatever the client asked for. Redeeming the same authorization code a second time
// means the code leaked, so it must also end the session the first redemption started.
func TestOAuthReadOnlyConsent(t *testing.T) {
	logsOnFailure(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	client := newOAuthClient(ctx, t)
	code, verifier := client.authorize(ctx, false)
	tokens := client.exchange(ctx, code, verifier)
	assert.Equal(t, []string{scopeRead}, strings.Fields(tokens.Scope), "only read was approved")

	session := connect(ctx, t, client.resource, "Bearer "+tokens.AccessToken, client.browser.Transport)

	var groups []api.Group
	decodeResult(t, "list_groups", callTool(ctx, t, session, "list_groups", nil), &groups)
	assert.NotEmpty(t, groups, "every account has at least the All group")

	name := uniqueName("mcp-e2e-readonly")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		deleteGroupIfPresent(t, groupNamed(ctx, t, name))
	})
	res := callTool(ctx, t, session, "create_group", map[string]any{"name": name})
	assert.True(t, res.IsError, "a read-only connection must not run a write tool")
	assert.Contains(t, resultText(t, res), "read only", "the tool error tells the user how to get write access")
	assert.Empty(t, groupNamed(ctx, t, name), "the refused write must not reach the account")

	status, body := client.tokenRequest(ctx, client.codeForm(code, verifier))
	assert.Equal(t, http.StatusBadRequest, status, "an authorization code is single use: %s", body)
	assert.Contains(t, body, "invalid_grant", "a replayed code is an invalid grant")
	status, _ = probe(ctx, t, client.browser, client.resource, "Bearer "+tokens.AccessToken)
	assert.Equal(t, http.StatusUnauthorized, status, "a replayed code must revoke the session its first use started")
}

// Declining on the consent page goes back to the client with access_denied and never
// reaches the identity provider. The decision is only taken from the consent page itself:
// a cross-site form post is refused before it is read.
func TestOAuthConsentDeclinedOrForged(t *testing.T) {
	logsOnFailure(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	client := newOAuthClient(ctx, t)

	forged := client.decide(ctx, client.consent(ctx), url.Values{"action": {"approve"}, "write": {"on"}}, "cross-site")
	assert.Equal(t, http.StatusForbidden, forged.status, "a cross-site consent post must be refused: %s", forged.body)

	step := client.consent(ctx)
	declined := client.decide(ctx, step, url.Values{"action": {"deny"}}, "same-origin")
	loc, ok := declined.redirectsToClient()
	require.True(t, ok, "declining returns to the client, got %d at %s: %s", declined.status, declined.url, declined.body)
	assert.Equal(t, "access_denied", loc.Query().Get("error"), "the client learns the user declined")
	assert.Equal(t, step.state, loc.Query().Get("state"), "the client's state comes back unchanged")
	assert.Empty(t, loc.Query().Get("code"), "no code is issued for a declined request")
}
