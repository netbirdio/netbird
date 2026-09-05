//go:build e2e

package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// joinGroup places the PAT's own user into the group so caller-scoped answers
// (GET /api/agent-network/agent-config) see the policies sourced from it, and
// restores the previous auto-groups on cleanup. Self-service updates of one's
// own auto_groups are permitted for every role, so this needs no second user.
func joinGroup(t *testing.T, ctx context.Context, groupID string) {
	t.Helper()
	me, err := srv.API().Users.Current(ctx)
	require.NoError(t, err, "read current user")
	before := append([]string(nil), me.AutoGroups...)
	_, err = srv.API().Users.Update(ctx, me.Id, api.PutApiUsersUserIdJSONRequestBody{
		Role:       me.Role,
		IsBlocked:  me.IsBlocked,
		AutoGroups: append(append([]string(nil), before...), groupID),
	})
	require.NoError(t, err, "add the caller to the policy source group")
	t.Cleanup(func() {
		_, _ = srv.API().Users.Update(context.Background(), me.Id, api.PutApiUsersUserIdJSONRequestBody{
			Role:       me.Role,
			IsBlocked:  me.IsBlocked,
			AutoGroups: before,
		})
	})
}

// configProvider returns the agent-config entry for the named provider, nil
// when the answer does not offer it. The suite shares one account, so other
// tests' fixtures may add unrelated providers to the caller's answer.
func configProvider(cfg api.AgentNetworkAgentConfig, name string) *api.AgentNetworkAgentConfigProvider {
	for i := range cfg.Providers {
		if cfg.Providers[i].Name == name {
			return &cfg.Providers[i]
		}
	}
	return nil
}

// TestAgentConfigAllowlistOfDeclaredModels reproduces the post-#7221 field
// report: a provider carrying a declared model set plus a policy guardrail
// whose allowlist holds those same declared ids must advertise the models on
// GET /api/agent-network/agent-config — the guardrail was built FROM the
// provider's model list (the dashboard's allowlist picker persists the
// declared ids verbatim), so nothing about the setup excludes them.
//
// The plain case passes today. The path-style case (Bedrock; Vertex has the
// same shape) fails: the declared id is compared through the proxy parser's
// canonical form (region prefix and version suffix stripped) while the
// allowlist entry is not, so the raw-vs-raw pair never intersects and the
// caller sees an empty model list. The same one-sided normalization sits in
// policyPermitsModel, so the proxy also denies the model at request time —
// the guardrail meant to allow exactly this model turns it off end to end.
func TestAgentConfigAllowlistOfDeclaredModels(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		catalogID string
		upstream  string
		declared  string
	}{
		{
			name:      "plain-declared-id",
			catalogID: "openai_api",
			upstream:  "https://api.openai.com",
			declared:  "gpt-4o-mini",
		},
		{
			// The operator declares the id AWS issues — region-prefixed
			// inference profile with a version suffix — and the allowlist
			// picker copies it as-is.
			name:      "bedrock-declared-id",
			catalogID: "bedrock_api",
			upstream:  "https://bedrock-runtime.eu-central-1.amazonaws.com",
			declared:  "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-agentcfg-" + tc.name})
			require.NoError(t, err, "create source group")
			t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

			joinGroup(t, ctx, grp.Id)

			providerName := "e2e-agentcfg-" + tc.name
			prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
				Name:        providerName,
				ProviderId:  tc.catalogID,
				UpstreamUrl: tc.upstream,
				ApiKey:      ptr("sk-dummy-e2e-key"),
				Enabled:     ptr(true),
				Models:      &[]api.AgentNetworkProviderModel{{Id: tc.declared, InputPer1k: 0.001, OutputPer1k: 0.002}},
			})
			require.NoError(t, err, "create provider")
			t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

			// Allowlist exactly the declared model, the way the dashboard
			// builds a guardrail from the provider's model list.
			var gr api.AgentNetworkGuardrailRequest
			gr.Name = "e2e-agentcfg-" + tc.name
			gr.Checks.ModelAllowlist.Enabled = true
			gr.Checks.ModelAllowlist.Models = []string{tc.declared}
			guard, err := srv.CreateGuardrail(ctx, gr)
			require.NoError(t, err, "create guardrail")
			t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

			pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
				Name:                   "e2e-agentcfg-" + tc.name,
				Enabled:                ptr(true),
				SourceGroups:           []string{grp.Id},
				DestinationProviderIds: []string{prov.Id},
				GuardrailIds:           &[]string{guard.Id},
			})
			require.NoError(t, err, "create policy")
			t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

			cfg, err := srv.GetAgentConfig(ctx)
			require.NoError(t, err, "read the caller-scoped agent config")
			require.True(t, cfg.Configured, "the account endpoint is bootstrapped by TestMain")

			entry := configProvider(cfg, providerName)
			require.NotNil(t, entry, "the policy authorizes the caller for the provider, so it must be offered")
			assert.False(t, entry.AllModelsAllowed, "an allowlist guardrail restricts the provider")
			assert.Equal(t, []string{tc.declared}, entry.Models,
				"the allowlist holds the provider's own declared id, so that model must be advertised")
		})
	}
}
