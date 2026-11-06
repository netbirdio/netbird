//go:build e2e

package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestAgentNetworkUsageSetupKeyPeer drives `netbird agent-network usage`
// inside a real client: CLI -> daemon -> management GetAgentNetworkInfo. The
// harness joins clients with setup keys, so the peer has no user and the
// answer is NO_USER. Limits need a user-owned peer, which the harness cannot
// register; the management real-store tests cover those.
func TestAgentNetworkUsageSetupKeyPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-usage"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-usage-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")

	cl, err := harness.StartClient(ctx, srv, sk.Key, harness.WithClientName("usage-client"))
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })
	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")

	code, out, err := cl.Exec(ctx, "netbird", "agent-network", "usage")
	require.NoError(t, err)
	assert.Equal(t, 0, code, "NO_USER is an answer, not a failure: %s", out)
	assert.Contains(t, out, "Agent Networks usage is not available for this peer", "setup-key peer must get the no-user text")

	code, out, err = cl.Exec(ctx, "netbird", "agent-network", "usage", "--json")
	require.NoError(t, err)
	require.Equal(t, 0, code, "json output: %s", out)
	var resp struct {
		State     string            `json:"state"`
		Providers []json.RawMessage `json:"providers"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &resp), "--json must print only JSON: %s", out)
	assert.Equal(t, "NO_USER", resp.State)
	assert.Empty(t, resp.Providers, "a peer without a user must not see providers")
}
