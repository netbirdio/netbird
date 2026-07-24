package agentnetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

// policyForProviders builds an enabled policy authorising the given providers
// under the given guardrails (both optional). Groups are irrelevant to
// buildProviderAllowlists, which keys purely on destination provider.
func policyForProviders(id string, guardrailIDs []string, providerIDs ...string) *types.Policy {
	return &types.Policy{
		ID:                     id,
		Enabled:                true,
		DestinationProviderIDs: providerIDs,
		GuardrailIDs:           guardrailIDs,
	}
}

func TestBuildProviderAllowlists(t *testing.T) {
	byID := map[string]*types.Guardrail{
		"g-4o":       allowlistGuardrail("g-4o", "acc-1", "gpt-4o"),
		"g-opus":     allowlistGuardrail("g-opus", "acc-1", "claude-opus-4"),
		"g-disabled": {ID: "g-disabled", Checks: types.GuardrailChecks{ModelAllowlist: types.GuardrailModelAllowlist{Enabled: false, Models: []string{"gpt-4o"}}}},
	}

	t.Run("all authorising policies restrict yields per-provider union", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x"),
			policyForProviders("p2", []string{"g-opus"}, "prov-x"),
		}
		got := buildProviderAllowlists(policies, byID)
		assert.Equal(t, map[string][]string{"prov-x": {"claude-opus-4", "gpt-4o"}}, got,
			"a provider every policy restricts carries the sorted union of their models")
	})

	t.Run("any un-guardrailed policy leaves the provider unrestricted (omitted)", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x"),
			policyForProviders("p2", nil, "prov-x"), // no guardrail
		}
		got := buildProviderAllowlists(policies, byID)
		assert.NotContains(t, got, "prov-x",
			"a provider reachable by an un-guardrailed policy must be omitted so the proxy treats it as unrestricted")
	})

	t.Run("a disabled allowlist counts as unrestricted", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-disabled"}, "prov-x"),
		}
		got := buildProviderAllowlists(policies, byID)
		assert.NotContains(t, got, "prov-x",
			"a policy whose only guardrail has a disabled allowlist is unrestricted")
	})

	t.Run("providers are isolated from one another", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x"),
			policyForProviders("p2", []string{"g-opus"}, "prov-y"),
		}
		got := buildProviderAllowlists(policies, byID)
		assert.Equal(t, []string{"gpt-4o"}, got["prov-x"], "prov-x keeps only its own model")
		assert.Equal(t, []string{"claude-opus-4"}, got["prov-y"], "prov-y keeps only its own model")
	})

	t.Run("one policy authorising two providers restricts both", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x", "prov-y"),
		}
		got := buildProviderAllowlists(policies, byID)
		assert.Equal(t, []string{"gpt-4o"}, got["prov-x"])
		assert.Equal(t, []string{"gpt-4o"}, got["prov-y"])
	})
}
