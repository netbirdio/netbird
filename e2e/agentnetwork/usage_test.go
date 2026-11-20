//go:build e2e

package agentnetwork

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestAgentNetworkUsageSetupKeyPeer drives `netbird agent-network usage`
// inside a real client: CLI -> daemon -> management GetAgentNetworkInfo. The
// harness joins clients with setup keys, so the peer has no user. Management
// answers it from its peer groups, with the peer id as the usage principal,
// so the policy's user and group caps both come back as limit rows.
func TestAgentNetworkUsageSetupKeyPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-usage"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	// A private upstream skips the credential check; nothing here sends a
	// request through the proxy.
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-usage-provider",
		ProviderId:  "openai_api",
		UpstreamUrl: "https://10.255.255.1",
		ApiKey:      ptr("sk-dummy-e2e-key"),
		Enabled:     ptr(true),
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-usage",
		Enabled:                ptr(true),
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
		Limits: &api.AgentNetworkPolicyLimits{
			TokenLimit: api.AgentNetworkPolicyTokenLimit{
				Enabled:       true,
				UserCap:       100_000,
				GroupCap:      500_000,
				WindowSeconds: 3600,
			},
		},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

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
	require.Equal(t, 0, code, "usage: %s", out)
	assert.Contains(t, out, "e2e-usage-provider (openai_api)", "setup-key peer must see the provider its group reaches")
	assert.Contains(t, out, "0 / 100,000 tokens", "user cap row: %s", out)
	assert.Contains(t, out, "0 / 500,000 tokens", "group cap row: %s", out)

	code, out, err = cl.Exec(ctx, "netbird", "agent-network", "usage", "--json")
	require.NoError(t, err)
	require.Equal(t, 0, code, "json output: %s", out)
	type providerUsage struct {
		Name      string `json:"name"`
		Exhausted bool   `json:"exhausted"`
		Limits    []struct {
			Cap float64 `json:"cap"`
		} `json:"limits"`
	}
	var resp struct {
		State     string          `json:"state"`
		Providers []providerUsage `json:"providers"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &resp), "--json must print only JSON: %s", out)
	assert.Equal(t, "OK", resp.State)
	idx := slices.IndexFunc(resp.Providers, func(p providerUsage) bool { return p.Name == "e2e-usage-provider" })
	require.GreaterOrEqual(t, idx, 0, "provider must be listed: %s", out)
	p := resp.Providers[idx]
	assert.False(t, p.Exhausted, "nothing spent yet")
	caps := make([]float64, 0, len(p.Limits))
	for _, l := range p.Limits {
		caps = append(caps, l.Cap)
	}
	assert.ElementsMatch(t, []float64{100_000, 500_000}, caps, "user and group caps are both listed")
}
