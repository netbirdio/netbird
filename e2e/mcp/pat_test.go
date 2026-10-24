//go:build e2e

package mcpe2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// A personal access token needs no OAuth: the MCP endpoint sits behind the same auth
// middleware as the REST API. The tools a model starts with must be advertised, a read
// must return the caller's own data, and a write must land in the account exactly as the
// REST call would, which the REST API then confirms.
func TestPATReadAndWriteTools(t *testing.T) {
	logsOnFailure(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	session := connect(ctx, t, srv.BaseURL+mcpPath, "Token "+srv.PAT, nil)

	names := toolNames(ctx, t, session)
	for _, want := range []string{"list_peers", "get_current_user", "list_groups", "create_group", "delete_group"} {
		assert.Contains(t, names, want, "tools/list must advertise %s", want)
	}

	var me api.User
	decodeResult(t, "get_current_user", callTool(ctx, t, session, "get_current_user", nil), &me)
	restMe, err := srv.API().Users.Current(ctx)
	require.NoError(t, err)
	assert.Equal(t, restMe.Id, me.Id, "get_current_user must return the PAT's owner")
	assert.Equal(t, harness.AdminEmail, me.Email, "the PAT belongs to the bootstrapped admin")

	name := uniqueName("mcp-e2e-pat")
	var created api.Group
	decodeResult(t, "create_group", callTool(ctx, t, session, "create_group", map[string]any{"name": name}), &created)
	require.NotEmpty(t, created.Id, "create_group returns the new group")
	t.Cleanup(func() { deleteGroupIfPresent(t, created.Id) })

	stored, err := srv.API().Groups.Get(ctx, created.Id)
	require.NoError(t, err, "the group created over MCP must be readable over REST")
	assert.Equal(t, name, stored.Name, "REST must show the name sent over MCP")

	res := callTool(ctx, t, session, "delete_group", map[string]any{"group_id": created.Id})
	require.False(t, res.IsError, "delete_group failed: %s", resultText(t, res))
	assert.False(t, groupExists(ctx, t, created.Id), "the group deleted over MCP must be gone from REST")
}
