//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/mcpapi"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// mcp.sql holds two accounts. Account A is testAccountId with the users the token mock maps
// to it; account B is otherAccountId, whose admin is otherUserId.
const (
	mcpTestData = "../testdata/mcp.sql"

	otherAccountID = "otherAccountId"
	otherPeerID    = "otherPeerId"
	otherGroupID   = "otherGroupId"
	otherKeyID     = "otherKeyId"
)

// mcpDeniedPattern matches the tool error the MCP endpoint returns for a REST call refused
// as forbidden or not found. Some handlers report an unknown ID as a 400 saying not found.
const mcpDeniedPattern = `failed with HTTP (40[34]:|400: .*not found)`

// accountObjects names one object of each kind an account holds in mcp.sql.
type accountObjects struct {
	accountID string
	peerID    string
	groupID   string
	groupName string
	keyID     string
}

var (
	accountA = accountObjects{
		accountID: testing_tools.TestAccountId,
		peerID:    testing_tools.TestPeerId,
		groupID:   testing_tools.TestGroupId,
		groupName: "testGroupName",
		keyID:     testing_tools.TestKeyId,
	}
	accountB = accountObjects{
		accountID: otherAccountID,
		peerID:    otherPeerID,
		groupID:   otherGroupID,
		groupName: "otherGroupName",
		keyID:     otherKeyID,
	}
)

// mcpServer is the management API with the MCP endpoint mounted the way BaseServer mounts
// it: behind the API authentication, replaying tool calls against the API router.
type mcpServer struct {
	handler http.Handler
	store   store.Store
}

func newMCPServer(t *testing.T) mcpServer {
	t.Helper()
	root, apiRouter, am := channel.BuildApiBlackBoxWithRouters(t, mcpTestData)
	require.NoError(t, mcpapi.RegisterEndpoints(apiRouter, apiRouter, mcpapi.Options{}), "mount the MCP endpoint")
	return mcpServer{handler: root, store: am.GetStore()}
}

func bearer(token string) string {
	return "Bearer " + token
}

// patOf stores a personal access token for the user and returns its Authorization header.
func (s mcpServer) patOf(t *testing.T, userID string) string {
	t.Helper()
	pat, err := types.CreateNewPAT("mcp-integration", 30, userID, userID)
	require.NoError(t, err)
	require.NoError(t, s.store.SavePAT(context.Background(), &pat.PersonalAccessToken))
	return "Token " + pat.PlainToken
}

// post sends one JSON-RPC message to the MCP endpoint.
func (s mcpServer) post(t *testing.T, authorization, query, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/mcp"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func toolCallBody(t *testing.T, tool string, args any) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": args},
	})
	require.NoError(t, err)
	return string(encoded)
}

type toolResult struct {
	IsError bool `json:"isError"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (r toolResult) text() string {
	parts := make([]string, 0, len(r.Content))
	for _, c := range r.Content {
		parts = append(parts, c.Text)
	}
	return strings.Join(parts, "\n")
}

// callTool runs tools/call over HTTP and returns the tool result. Transport and JSON-RPC
// errors fail the test: callers assert on what the tool itself returned.
func (s mcpServer) callTool(t *testing.T, authorization, tool string, args any) toolResult {
	t.Helper()
	rec := s.post(t, authorization, "", toolCallBody(t, tool, args))
	require.Equal(t, http.StatusOK, rec.Code, "tools/call %s over HTTP: %s", tool, rec.Body.String())

	var resp struct {
		Result *toolResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), "JSON-RPC response: %s", rec.Body.String())
	require.Nil(t, resp.Error, "tools/call %s returned a JSON-RPC error: %s", tool, rec.Body.String())
	require.NotNil(t, resp.Result, "tools/call %s returned no result: %s", tool, rec.Body.String())
	return *resp.Result
}

// callToolOK runs the tool, requires it to succeed and returns its JSON text.
func (s mcpServer) callToolOK(t *testing.T, authorization, tool string, args any) string {
	t.Helper()
	res := s.callTool(t, authorization, tool, args)
	require.False(t, res.IsError, "%s must succeed: %s", tool, res.text())
	return res.text()
}

// assertToolDenied asserts the tool failed with the REST API's not found or forbidden.
func assertToolDenied(t *testing.T, tool string, res toolResult) {
	t.Helper()
	assert.True(t, res.IsError, "%s must fail, got: %s", tool, res.text())
	assert.Regexp(t, mcpDeniedPattern, res.text(), "%s must fail as forbidden or not found", tool)
}

// listIDs runs a list tool without arguments and returns the id of every object it lists.
func (s mcpServer) listIDs(t *testing.T, authorization, tool string) []string {
	t.Helper()
	text := s.callToolOK(t, authorization, tool, map[string]any{})
	var objects []struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal([]byte(text), &objects), "%s returns a JSON array: %s", tool, text)
	ids := make([]string, 0, len(objects))
	for _, o := range objects {
		ids = append(ids, o.ID)
	}
	return ids
}

// assertAccountObjectsIntact checks the store still holds the account's objects as mcp.sql
// created them.
func assertAccountObjectsIntact(t *testing.T, s store.Store, objects accountObjects) {
	t.Helper()
	ctx := context.Background()

	group, err := s.GetGroupByID(ctx, store.LockingStrengthNone, objects.accountID, objects.groupID)
	if assert.NoError(t, err, "group %s must still exist", objects.groupID) {
		assert.Equal(t, objects.groupName, group.Name, "group %s must keep its name", objects.groupID)
		assert.Equal(t, []string{objects.peerID}, group.Peers, "group %s must keep its peers", objects.groupID)
	}

	peer, err := s.GetPeerByID(ctx, store.LockingStrengthNone, objects.accountID, objects.peerID)
	if assert.NoError(t, err, "peer %s must still exist", objects.peerID) {
		assert.NotEqual(t, "hijacked", peer.Name, "peer %s must keep its name", objects.peerID)
		assert.False(t, peer.SSHEnabled, "peer %s must keep SSH disabled", objects.peerID)
	}

	key, err := s.GetSetupKeyByID(ctx, store.LockingStrengthNone, objects.accountID, objects.keyID)
	if assert.NoError(t, err, "setup key %s must still exist", objects.keyID) {
		assert.False(t, key.Revoked, "setup key %s must not be revoked", objects.keyID)
		assert.Equal(t, []string{objects.groupID}, key.AutoGroups, "setup key %s must keep its auto groups", objects.keyID)
	}
}

// Test_MCP_ToolsStayInCallerAccount runs every kind of tool an admin of one account could aim
// at another account's objects, and checks that reads see only the caller's account and writes
// to the other account's IDs fail without touching them.
func Test_MCP_ToolsStayInCallerAccount(t *testing.T) {
	callers := []struct {
		name          string
		authorization func(t *testing.T, s mcpServer) string
		own, foreign  accountObjects
	}{
		{
			name:          "Admin of account A with a JWT",
			authorization: func(*testing.T, mcpServer) string { return bearer(testing_tools.TestAdminId) },
			own:           accountA,
			foreign:       accountB,
		},
		{
			name:          "Admin of account B with a JWT",
			authorization: func(*testing.T, mcpServer) string { return bearer(testing_tools.OtherUserId) },
			own:           accountB,
			foreign:       accountA,
		},
		{
			name: "Admin of account B with a PAT",
			authorization: func(t *testing.T, s mcpServer) string {
				return s.patOf(t, testing_tools.OtherUserId)
			},
			own:     accountB,
			foreign: accountA,
		},
	}

	for _, caller := range callers {
		t.Run(caller.name, func(t *testing.T) {
			srv := newMCPServer(t)
			auth := caller.authorization(t, srv)
			own, foreign := caller.own, caller.foreign

			assert.Equal(t, []string{own.peerID}, srv.listIDs(t, auth, "list_peers"), "list_peers lists only the caller's peers")
			groups := srv.listIDs(t, auth, "list_groups")
			assert.Contains(t, groups, own.groupID, "list_groups lists the caller's groups")
			assert.NotContains(t, groups, foreign.groupID, "list_groups does not list the other account's groups")
			assert.Equal(t, []string{own.keyID}, srv.listIDs(t, auth, "list_setup_keys"), "list_setup_keys lists only the caller's setup keys")

			// The caller's own objects are reachable, so a refusal below is about the account.
			srv.callToolOK(t, auth, "get_peer", map[string]any{"peer_id": own.peerID})
			srv.callToolOK(t, auth, "get_group", map[string]any{"group_id": own.groupID})
			srv.callToolOK(t, auth, "get_setup_key", map[string]any{"key_id": own.keyID})

			crossAccount := []struct {
				tool string
				args map[string]any
			}{
				{"get_peer", map[string]any{"peer_id": foreign.peerID}},
				{"get_group", map[string]any{"group_id": foreign.groupID}},
				{"get_setup_key", map[string]any{"key_id": foreign.keyID}},
				{"update_peer", map[string]any{
					"peer_id": foreign.peerID, "name": "hijacked", "ssh_enabled": true,
					"login_expiration_enabled": false, "inactivity_expiration_enabled": false,
				}},
				{"update_group", map[string]any{"group_id": foreign.groupID, "name": "hijacked", "peers": []string{}}},
				{"update_setup_key", map[string]any{"key_id": foreign.keyID, "revoked": true, "auto_groups": []string{}}},
				{"delete_group", map[string]any{"group_id": foreign.groupID}},
				{"delete_setup_key", map[string]any{"key_id": foreign.keyID}},
				{"delete_peer", map[string]any{"peer_id": foreign.peerID}},
			}
			for _, tc := range crossAccount {
				assertToolDenied(t, tc.tool, srv.callTool(t, auth, tc.tool, tc.args))
			}

			// For an admin the REST handler computes what the ID reaches inside the caller's own
			// account, which for another account's peer is nothing.
			res := srv.callTool(t, auth, "list_accessible_peers", map[string]any{"peer_id": foreign.peerID})
			assert.False(t, res.IsError, "list_accessible_peers must answer with an empty list, got: %s", res.text())
			assert.Equal(t, "[]", res.text(), "list_accessible_peers reveals nothing of the other account")

			assertAccountObjectsIntact(t, srv.store, foreign)
			assertAccountObjectsIntact(t, srv.store, own)
		})
	}
}

// Test_MCP_ReferencesToOtherAccountAreRefused checks that a write in the caller's own account
// cannot pull in objects of another account by ID.
func Test_MCP_ReferencesToOtherAccountAreRefused(t *testing.T) {
	srv := newMCPServer(t)
	auth := bearer(testing_tools.TestAdminId)
	ctx := context.Background()

	groupsBefore, err := srv.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	keysBefore, err := srv.store.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)

	res := srv.callTool(t, auth, "create_group", map[string]any{"name": "with-foreign-peer", "peers": []string{accountB.peerID}})
	assert.True(t, res.IsError, "a group cannot hold another account's peer, got: %s", res.text())

	res = srv.callTool(t, auth, "create_setup_key", map[string]any{
		"name": "with-foreign-group", "type": "reusable", "expires_in": 86400,
		"auto_groups": []string{accountB.groupID}, "usage_limit": 0,
	})
	assert.True(t, res.IsError, "a setup key cannot auto-assign another account's group, got: %s", res.text())

	// The same update with only the account's own peer goes through, so the refusal below is
	// about the foreign peer and not about the update itself.
	srv.callToolOK(t, auth, "update_group", map[string]any{
		"group_id": accountA.groupID, "name": accountA.groupName, "peers": []string{accountA.peerID},
	})
	res = srv.callTool(t, auth, "update_group", map[string]any{
		"group_id": accountA.groupID, "name": accountA.groupName, "peers": []string{accountA.peerID, accountB.peerID},
	})
	assert.True(t, res.IsError, "an existing group cannot take in another account's peer, got: %s", res.text())
	assert.Contains(t, res.text(), "failed with HTTP 422", "the foreign peer is rejected as unknown, got: %s", res.text())

	groupsAfter, err := srv.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	assert.Len(t, groupsAfter, len(groupsBefore), "no group was created in account A")
	for _, group := range groupsAfter {
		assert.NotContains(t, group.Peers, accountB.peerID, "group %s of account A must not hold account B's peer", group.ID)
	}
	keysAfter, err := srv.store.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	assert.Len(t, keysAfter, len(keysBefore), "no setup key was created in account A")

	assertAccountObjectsIntact(t, srv.store, accountA)
	assertAccountObjectsIntact(t, srv.store, accountB)
}

// accountSettingsOf returns the settings object get_account reports for the caller's account.
func accountSettingsOf(t *testing.T, srv mcpServer, authorization string) map[string]any {
	t.Helper()
	text := srv.callToolOK(t, authorization, "get_account", map[string]any{})
	var accounts []struct {
		ID       string         `json:"id"`
		Settings map[string]any `json:"settings"`
	}
	require.NoError(t, json.Unmarshal([]byte(text), &accounts), "get_account returns a JSON array: %s", text)
	require.Len(t, accounts, 1, "get_account returns exactly the caller's account")
	return accounts[0].Settings
}

func peerLoginExpirationOf(t *testing.T, s store.Store, accountID string) time.Duration {
	t.Helper()
	settings, err := s.GetAccountSettings(context.Background(), store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	return settings.PeerLoginExpiration
}

// Test_MCP_UpdateAccountTargetsCallerAccount checks that update_account takes the account
// from the caller's identity, so each admin changes only their own account.
func Test_MCP_UpdateAccountTargetsCallerAccount(t *testing.T) {
	srv := newMCPServer(t)
	adminA := bearer(testing_tools.TestAdminId)
	adminB := bearer(testing_tools.OtherUserId)

	// mcp.sql gives both accounts a 24h peer login expiration.
	initial := 24 * time.Hour
	require.Equal(t, initial, peerLoginExpirationOf(t, srv.store, accountA.accountID), "precondition: account A")
	require.Equal(t, initial, peerLoginExpirationOf(t, srv.store, accountB.accountID), "precondition: account B")

	settingsA := accountSettingsOf(t, srv, adminA)
	settingsA["peer_login_expiration"] = 7200
	srv.callToolOK(t, adminA, "update_account", map[string]any{"settings": settingsA})
	assert.Equal(t, 2*time.Hour, peerLoginExpirationOf(t, srv.store, accountA.accountID), "admin of A updates account A")
	assert.Equal(t, initial, peerLoginExpirationOf(t, srv.store, accountB.accountID), "admin of A leaves account B unchanged")

	settingsB := accountSettingsOf(t, srv, adminB)
	settingsB["peer_login_expiration"] = 10800
	srv.callToolOK(t, adminB, "update_account", map[string]any{"settings": settingsB})
	assert.Equal(t, 3*time.Hour, peerLoginExpirationOf(t, srv.store, accountB.accountID), "admin of B updates account B")
	assert.Equal(t, 2*time.Hour, peerLoginExpirationOf(t, srv.store, accountA.accountID), "admin of B leaves account A unchanged")
}

// Test_MCP_RegularUserCannotWrite checks that a user without the admin role is refused the
// write tools the REST API reserves for admins, and that the refusal changes nothing.
func Test_MCP_RegularUserCannotWrite(t *testing.T) {
	srv := newMCPServer(t)
	admin := bearer(testing_tools.TestAdminId)
	regular := bearer(testing_tools.TestUserId)
	ctx := context.Background()

	settings := accountSettingsOf(t, srv, admin)
	settings["peer_login_expiration"] = 7200
	newKey := map[string]any{"name": "mcp-key", "type": "reusable", "expires_in": 86400, "auto_groups": []string{}, "usage_limit": 0}

	keysBefore, err := srv.store.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	groupsBefore, err := srv.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)

	writes := []struct {
		tool string
		args map[string]any
	}{
		{"create_setup_key", newKey},
		{"update_account", map[string]any{"settings": settings}},
		{"create_group", map[string]any{"name": "regular-user-group", "peers": []string{}}},
		{"update_group", map[string]any{"group_id": accountA.groupID, "name": "hijacked", "peers": []string{}}},
		{"delete_group", map[string]any{"group_id": accountA.groupID}},
		{"delete_setup_key", map[string]any{"key_id": accountA.keyID}},
	}
	for _, w := range writes {
		res := srv.callTool(t, regular, w.tool, w.args)
		assert.True(t, res.IsError, "%s must be refused to a regular user, got: %s", w.tool, res.text())
		assert.Contains(t, res.text(), "failed with HTTP 403", "%s is refused by the REST permission check", w.tool)
	}

	keysAfter, err := srv.store.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	assert.Len(t, keysAfter, len(keysBefore), "a regular user creates no setup key")
	groupsAfter, err := srv.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	assert.Len(t, groupsAfter, len(groupsBefore), "a regular user creates or deletes no group")
	assert.Equal(t, 24*time.Hour, peerLoginExpirationOf(t, srv.store, accountA.accountID), "a regular user does not change the account")
	assertAccountObjectsIntact(t, srv.store, accountA)

	// The same arguments succeed for an admin, so the refusals above came from the role and
	// not from the arguments.
	srv.callToolOK(t, admin, "create_setup_key", newKey)
	keysAfter, err = srv.store.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	assert.Len(t, keysAfter, len(keysBefore)+1, "an admin creates the setup key")
	srv.callToolOK(t, admin, "update_account", map[string]any{"settings": settings})
	assert.Equal(t, 2*time.Hour, peerLoginExpirationOf(t, srv.store, accountA.accountID), "an admin changes the account")
}

// Test_MCP_AccountQueryCannotSwitchAccount checks the ?account= tenant URL. Nothing in a
// self-hosted deployment switches accounts, so any account but the caller's is refused
// before a tool runs, and a malformed one is refused rather than ignored.
func Test_MCP_AccountQueryCannotSwitchAccount(t *testing.T) {
	srv := newMCPServer(t)
	listGroups := toolCallBody(t, "list_groups", map[string]any{})

	cases := []struct {
		name          string
		authorization string
		query         string
		wantStatus    int
	}{
		{"user of A asking for account B", bearer(testing_tools.TestAdminId), "?account=" + accountB.accountID, http.StatusForbidden},
		{"user of B asking for account A", bearer(testing_tools.OtherUserId), "?account=" + accountA.accountID, http.StatusForbidden},
		{"empty account", bearer(testing_tools.TestAdminId), "?account=", http.StatusBadRequest},
		{"miscased account key", bearer(testing_tools.TestAdminId), "?Account=" + accountB.accountID, http.StatusBadRequest},
		{"unparseable escape", bearer(testing_tools.TestAdminId), "?account=" + accountB.accountID + "%", http.StatusBadRequest},
		{"semicolon in query", bearer(testing_tools.TestAdminId), "?account=" + accountB.accountID + ";x=1", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := srv.post(t, tc.authorization, tc.query, listGroups)
			assert.Equal(t, tc.wantStatus, rec.Code, "status for %s: %s", tc.query, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), accountB.groupName, "no account B data in the response")
			assert.NotContains(t, rec.Body.String(), accountA.groupName, "no account A data in the response")
		})
	}

	t.Run("caller's own account", func(t *testing.T) {
		rec := srv.post(t, bearer(testing_tools.TestAdminId), "?account="+accountA.accountID, listGroups)
		require.Equal(t, http.StatusOK, rec.Code, "the caller's own account is served: %s", rec.Body.String())
		assert.Contains(t, rec.Body.String(), accountA.groupName, "tools run on the caller's account")
		assert.NotContains(t, rec.Body.String(), accountB.groupName, "no account B data in the response")
	})

	assertAccountObjectsIntact(t, srv.store, accountA)
	assertAccountObjectsIntact(t, srv.store, accountB)
}

// Test_MCP_BlockedUserIsRefused checks that a blocked user, here with the admin role, can
// neither read nor write through MCP tools. The authentication middleware lets a blocked JWT
// user through; the REST permission check behind every tool refuses them.
func Test_MCP_BlockedUserIsRefused(t *testing.T) {
	srv := newMCPServer(t)
	blocked := bearer(testing_tools.BlockedUserId)
	ctx := context.Background()

	groupsBefore, err := srv.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)

	calls := []struct {
		tool string
		args map[string]any
	}{
		{"list_peers", map[string]any{}},
		{"get_group", map[string]any{"group_id": accountA.groupID}},
		{"create_group", map[string]any{"name": "blocked-user-group", "peers": []string{}}},
		{"delete_group", map[string]any{"group_id": accountA.groupID}},
	}
	for _, c := range calls {
		res := srv.callTool(t, blocked, c.tool, c.args)
		assert.True(t, res.IsError, "%s must be refused to a blocked user, got: %s", c.tool, res.text())
		assert.Contains(t, res.text(), "failed with HTTP 403", "%s is refused as forbidden", c.tool)
		assert.Contains(t, res.text(), "user is blocked", "%s is refused because the user is blocked", c.tool)
	}

	groupsAfter, err := srv.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountA.accountID)
	require.NoError(t, err)
	assert.Len(t, groupsAfter, len(groupsBefore), "a blocked user creates or deletes no group")
	assertAccountObjectsIntact(t, srv.store, accountA)
}

// Test_MCP_PathArgumentStaysOnToolRoute checks that an ID equal to a literal segment of a
// sibling route cannot send a tool there. The API router registers GET /api/networks/routers
// and /api/networks/resources ahead of /api/networks/{networkId}, so get_network with those
// IDs would list all routers, a tool the NB_MCP_TOOLS allowlist may leave out, and all
// resources, an endpoint outside the public spec and the catalog.
func Test_MCP_PathArgumentStaysOnToolRoute(t *testing.T) {
	srv := newMCPServer(t)
	admin := bearer(testing_tools.TestAdminId)

	for _, id := range []string{"routers", "resources"} {
		res := srv.callTool(t, admin, "get_network", map[string]any{"network_id": id})
		assert.True(t, res.IsError, "get_network %q must not reach another route, got: %s", id, res.text())
		assert.Contains(t, res.text(), "another API route", "get_network %q is refused before dispatch", id)
	}

	created := srv.callToolOK(t, admin, "create_network", map[string]any{"name": "office"})
	var network struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal([]byte(created), &network), "create_network returns the network: %s", created)
	got := srv.callToolOK(t, admin, "get_network", map[string]any{"network_id": network.ID})
	assert.Contains(t, got, `"name":"office"`, "an ID still reaches get_network's own route")
}
