package agentnetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		got := buildProviderAllowlists(policies, byID, nil)
		assert.Equal(t, map[string][]string{"prov-x": {"claude-opus-4", "gpt-4o"}}, got,
			"a provider every policy restricts carries the sorted union of their models")
	})

	t.Run("any un-guardrailed policy leaves the provider unrestricted (omitted)", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x"),
			policyForProviders("p2", nil, "prov-x"), // no guardrail
		}
		got := buildProviderAllowlists(policies, byID, nil)
		assert.NotContains(t, got, "prov-x",
			"a provider reachable by an un-guardrailed policy must be omitted so the proxy treats it as unrestricted")
	})

	t.Run("a disabled allowlist counts as unrestricted", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-disabled"}, "prov-x"),
		}
		got := buildProviderAllowlists(policies, byID, nil)
		assert.NotContains(t, got, "prov-x",
			"a policy whose only guardrail has a disabled allowlist is unrestricted")
	})

	t.Run("providers are isolated from one another", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x"),
			policyForProviders("p2", []string{"g-opus"}, "prov-y"),
		}
		got := buildProviderAllowlists(policies, byID, nil)
		assert.Equal(t, []string{"gpt-4o"}, got["prov-x"], "prov-x keeps only its own model")
		assert.Equal(t, []string{"claude-opus-4"}, got["prov-y"], "prov-y keeps only its own model")
	})

	t.Run("one policy authorising two providers restricts both", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o"}, "prov-x", "prov-y"),
		}
		got := buildProviderAllowlists(policies, byID, nil)
		assert.Equal(t, []string{"gpt-4o"}, got["prov-x"])
		assert.Equal(t, []string{"gpt-4o"}, got["prov-y"])
	})

	t.Run("union across a single policy's guardrails", func(t *testing.T) {
		policies := []*types.Policy{
			policyForProviders("p1", []string{"g-4o", "g-opus"}, "prov-x"),
		}
		got := buildProviderAllowlists(policies, byID, nil)
		assert.ElementsMatch(t, []string{"claude-opus-4", "gpt-4o"}, got["prov-x"],
			"a policy's own multiple allowlist guardrails union together")
	})

	t.Run("an enabled allowlist with no models denies everything", func(t *testing.T) {
		empty := map[string]*types.Guardrail{"g-empty": allowlistGuardrail("g-empty", "acc-1")}
		got := buildProviderAllowlists([]*types.Policy{
			policyForProviders("p1", []string{"g-empty"}, "prov-x"),
		}, empty, nil)
		assert.Equal(t, map[string][]string{"prov-x": {}}, got,
			"an enabled-but-empty allowlist is restricted with an empty set, not unrestricted")
	})
}

// policyForGroups builds an enabled policy binding the given source groups to
// the given providers under an optional guardrail.
func policyForGroups(id string, groups []string, guardrailIDs []string, providerIDs ...string) *types.Policy {
	return &types.Policy{
		ID:                     id,
		Enabled:                true,
		SourceGroups:           groups,
		DestinationProviderIDs: providerIDs,
		GuardrailIDs:           guardrailIDs,
	}
}

// TestBuildModelPolicies covers the finer index discovery needs. Where
// buildProviderAllowlists flattens every authorising policy into one list per
// provider — enough for a fail-closed backstop, but blind to who is asking —
// this keeps each policy's source groups beside its models so the router can
// bound a listing to the calling groups.
func TestBuildModelPolicies(t *testing.T) {
	byID := map[string]*types.Guardrail{
		"g-4o":       allowlistGuardrail("g-4o", "acc-1", "gpt-4o"),
		"g-opus":     allowlistGuardrail("g-opus", "acc-1", "claude-opus-4"),
		"g-disabled": {ID: "g-disabled", Checks: types.GuardrailChecks{ModelAllowlist: types.GuardrailModelAllowlist{Enabled: false, Models: []string{"gpt-4o"}}}},
	}

	t.Run("each policy keeps its own groups and models", func(t *testing.T) {
		policies := []*types.Policy{
			policyForGroups("p1", []string{"grp-eng"}, []string{"g-4o"}, "prov-x"),
			policyForGroups("p2", []string{"grp-sales"}, []string{"g-opus"}, "prov-x"),
		}
		got := buildModelPolicies(policies, byID, nil)
		assert.Equal(t, []routerModelPolicy{
			{GroupIDs: []string{"grp-eng"}, Models: []string{"gpt-4o"}},
			{GroupIDs: []string{"grp-sales"}, Models: []string{"claude-opus-4"}},
		}, got["prov-x"],
			"the two policies must stay separable so neither group is offered the other's models")
	})

	t.Run("an unrestricted policy carries nil models", func(t *testing.T) {
		policies := []*types.Policy{
			policyForGroups("p1", []string{"grp-eng"}, []string{"g-4o"}, "prov-x"),
			policyForGroups("p2", []string{"grp-admin"}, nil, "prov-x"),
		}
		got := buildModelPolicies(policies, byID, nil)
		assert.Nil(t, got["prov-x"][1].Models,
			"no allowlist must reach the router as nil, which lifts the restriction for its groups")
	})

	t.Run("a disabled allowlist is not a restriction", func(t *testing.T) {
		policies := []*types.Policy{policyForGroups("p1", []string{"grp-eng"}, []string{"g-disabled"}, "prov-x")}
		got := buildModelPolicies(policies, byID, nil)
		assert.Nil(t, got["prov-x"][0].Models,
			"a guardrail with the allowlist check off restricts nothing")
	})

	t.Run("an enabled allowlist with no models permits nothing", func(t *testing.T) {
		byIDEmpty := map[string]*types.Guardrail{
			"g-empty": {ID: "g-empty", Checks: types.GuardrailChecks{ModelAllowlist: types.GuardrailModelAllowlist{Enabled: true}}},
		}
		policies := []*types.Policy{policyForGroups("p1", []string{"grp-eng"}, []string{"g-empty"}, "prov-x")}
		got := buildModelPolicies(policies, byIDEmpty, nil)
		require.NotNil(t, got["prov-x"][0].Models,
			"an empty allowlist must not arrive as nil — that would read as unrestricted")
		assert.Empty(t, got["prov-x"][0].Models)
	})

	t.Run("a policy binding no groups is skipped", func(t *testing.T) {
		policies := []*types.Policy{policyForGroups("p1", nil, []string{"g-4o"}, "prov-x")}
		assert.Empty(t, buildModelPolicies(policies, byID, nil),
			"a policy with no source groups authorises nobody, so it bounds nobody's listing")
	})
}

// TestSynthesizedAllowlists_ExpandDeclaredIDsPerProvider proves the
// synthesized allowlists carry the canonical form alongside a raw declared
// entry — under the destination provider's own catalog id, never another's —
// so the proxy-side compares (guardrail backstop, per-group router rules)
// admit the allowlist however the operator wrote it, while a plain provider's
// "-vN"- or "@"-suffixed entries stay verbatim and cannot widen.
func TestSynthesizedAllowlists_ExpandDeclaredIDsPerProvider(t *testing.T) {
	byID := map[string]*types.Guardrail{
		"g-raw": allowlistGuardrail("g-raw", "acc-1",
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			"claude-sonnet-4-5@20250929",
			"gpt-4o"),
	}
	catalogByProvider := map[string]string{
		"prov-bedrock": "bedrock_api",
		"prov-vertex":  "vertex_ai_api",
		"prov-plain":   "openai_api",
	}
	policies := []*types.Policy{
		policyForGroups("p1", []string{"grp-eng"}, []string{"g-raw"},
			"prov-bedrock", "prov-vertex", "prov-plain"),
	}

	t.Run("guardrail backstop expands under each provider's own normalizer", func(t *testing.T) {
		got := buildProviderAllowlists(policies, byID, catalogByProvider)
		assert.ElementsMatch(t, []string{
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			"anthropic.claude-sonnet-4-5",
			"claude-sonnet-4-5@20250929",
			"gpt-4o",
		}, got["prov-bedrock"],
			"the Bedrock destination strips geography/version, but must not apply Vertex's @-strip")
		assert.ElementsMatch(t, []string{
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			"claude-sonnet-4-5@20250929",
			"claude-sonnet-4-5",
			"gpt-4o",
		}, got["prov-vertex"],
			"the Vertex destination strips @version, but must not apply Bedrock's suffix strip")
		assert.ElementsMatch(t, []string{
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			"claude-sonnet-4-5@20250929",
			"gpt-4o",
		}, got["prov-plain"],
			"a body-routed provider keeps every entry verbatim — no alternate can widen it")
	})

	t.Run("router model rules expand the same way", func(t *testing.T) {
		got := buildModelPolicies(policies, byID, catalogByProvider)
		require.Len(t, got["prov-bedrock"], 1)
		assert.Contains(t, got["prov-bedrock"][0].Models, "anthropic.claude-sonnet-4-5")
		assert.NotContains(t, got["prov-bedrock"][0].Models, "claude-sonnet-4-5")
		require.Len(t, got["prov-vertex"], 1)
		assert.Contains(t, got["prov-vertex"][0].Models, "claude-sonnet-4-5")
		assert.NotContains(t, got["prov-vertex"][0].Models, "anthropic.claude-sonnet-4-5")
		require.Len(t, got["prov-plain"], 1)
		assert.ElementsMatch(t, []string{
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			"claude-sonnet-4-5@20250929",
			"gpt-4o",
		}, got["prov-plain"][0].Models)
	})
}
