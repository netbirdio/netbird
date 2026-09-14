package agentnetwork

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// guardedPolicy builds an enabled, uncapped policy that authorises sourceGroups
// to reach providerID under the given guardrails. Uncapped keeps the selector's
// headroom scoring trivial so these tests isolate the model-allowlist gate.
func guardedPolicy(id, account string, sourceGroups []string, providerID string, guardrailIDs ...string) *types.Policy {
	return &types.Policy{
		ID:                     id,
		AccountID:              account,
		Enabled:                true,
		SourceGroups:           sourceGroups,
		DestinationProviderIDs: []string{providerID},
		GuardrailIDs:           guardrailIDs,
		CreatedAt:              time.Now().UTC(),
	}
}

// allowlistGuardrail builds a guardrail whose model allowlist is enabled and
// carries the given models.
func allowlistGuardrail(id, account string, models ...string) *types.Guardrail {
	return &types.Guardrail{
		ID:        id,
		AccountID: account,
		Checks: types.GuardrailChecks{
			ModelAllowlist: types.GuardrailModelAllowlist{Enabled: true, Models: models},
		},
	}
}

func expectPolicies(mockStore *store.MockStore, account string, policies ...*types.Policy) {
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), account).
		Return(policies, nil)
}

func expectGuardrails(mockStore *store.MockStore, account string, guardrails ...*types.Guardrail) {
	mockStore.EXPECT().
		GetAccountAgentNetworkGuardrails(gomock.Any(), gomock.Any(), account).
		Return(guardrails, nil)
}

// expectProviderCatalog resolves the destination provider to the given
// catalog provider id, which picks the model-id normalizer the allowlist
// gate compares through. AnyTimes: the lookup runs only when the guardrail
// gate is reached.
func expectProviderCatalog(mockStore *store.MockStore, account, providerID, catalog string) {
	mockStore.EXPECT().
		GetAgentNetworkProviderByID(gomock.Any(), gomock.Any(), account, providerID).
		Return(&types.Provider{ID: providerID, AccountID: account, ProviderID: catalog}, nil).
		AnyTimes()
}

// TestSelectPolicy_ModelBlockedByAllowlist proves the authoritative allowlist
// decision: a policy authorises the (provider, group) but restricts the model,
// and the requested model isn't on the list, so the request is denied.
func TestSelectPolicy_ModelBlockedByAllowlist(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o"))
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "claude-opus-4",
	})
	require.NoError(t, err)
	assert.False(t, res.Allow, "a model outside the only applicable policy's allowlist must be denied")
	assert.Equal(t, denyCodeModelBlocked, res.DenyCode, "deny code must be model_blocked")
	assert.NotEmpty(t, res.DenyReason, "deny reason must be populated")
}

// TestSelectPolicy_ModelAllowedByAllowlist is the allow counterpart: the model
// is on the applicable policy's allowlist, so selection proceeds normally.
func TestSelectPolicy_ModelAllowedByAllowlist(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o", "claude-opus-4"))
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "claude-opus-4",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "a model on the applicable policy's allowlist must be allowed")
	assert.Equal(t, "pol-A", res.SelectedPolicyID)
}

// TestSelectPolicy_CaseInsensitiveModelMatch proves the compare tolerates case
// and surrounding whitespace, matching the proxy guardrail's normalisation.
func TestSelectPolicy_CaseInsensitiveModelMatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "  GPT-4o  "))
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "gpt-4o",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "case/whitespace variants must match the allowlist entry")
}

// TestSelectPolicy_UnguardedPolicyIsUnrestricted is the false-deny fix: when two
// policies authorise the same (provider, group) and one has no guardrail, that
// policy makes the request unrestricted — not caught by the other's allowlist.
func TestSelectPolicy_UnguardedPolicyIsUnrestricted(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	restricted := guardedPolicy("pol-restricted", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	open := guardedPolicy("pol-open", "acc-1", []string{"grp-eng"}, "prov-1") // no guardrail
	expectPolicies(mockStore, "acc-1", restricted, open)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o"))
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "claude-opus-4",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "an un-guardrailed policy for the same (provider, group) must leave the request unrestricted")
	assert.Equal(t, "pol-open", res.SelectedPolicyID, "the unrestricted policy must be the one that pays")
}

// TestSelectPolicy_AllowlistDoesNotLeakAcrossGroups is the false-allow fix: a
// model allowlisted only for grp-b must not be usable by a grp-a caller. The
// selector considers only policies applicable to the caller's groups.
func TestSelectPolicy_AllowlistDoesNotLeakAcrossGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	polA := guardedPolicy("pol-a", "acc-1", []string{"grp-a"}, "prov-1", "g-a")
	polB := guardedPolicy("pol-b", "acc-1", []string{"grp-b"}, "prov-1", "g-b")
	expectPolicies(mockStore, "acc-1", polA, polB)
	expectGuardrails(mockStore, "acc-1",
		allowlistGuardrail("g-a", "acc-1", "gpt-4o"),
		allowlistGuardrail("g-b", "acc-1", "claude-opus-4"),
	)
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-a"},
		ProviderID: "prov-1",
		Model:      "claude-opus-4", // only allowed for grp-b
	})
	require.NoError(t, err)
	assert.False(t, res.Allow, "grp-b's allowlisted model must not leak to a grp-a caller")
	assert.Equal(t, denyCodeModelBlocked, res.DenyCode)
}

// TestSelectPolicy_UndeterminedModelFailsClosed proves the fail-closed contract
// mirrors the proxy: with a restricted applicable policy and an empty model
// (e.g. a path-routed shape the parser couldn't map), the request is denied.
func TestSelectPolicy_UndeterminedModelFailsClosed(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o"))
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "", // undetermined
	})
	require.NoError(t, err)
	assert.False(t, res.Allow, "an undetermined model must fail closed against a restricted policy")
	assert.Equal(t, denyCodeModelBlocked, res.DenyCode)
}

// TestSelectPolicy_DisabledAllowlistDoesNotRestrict proves a guardrail whose
// model allowlist is disabled imposes no model restriction, even though the
// policy references it.
func TestSelectPolicy_DisabledAllowlistDoesNotRestrict(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	disabled := &types.Guardrail{
		ID:        "g-1",
		AccountID: "acc-1",
		Checks: types.GuardrailChecks{
			ModelAllowlist: types.GuardrailModelAllowlist{Enabled: false, Models: []string{"gpt-4o"}},
		},
	}
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", disabled)
	// Deliberately no provider expectation: with no enabled allowlist the
	// gate must skip the catalog-id lookup entirely.
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "anything-goes",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "a disabled allowlist must not restrict the model")
	assert.Equal(t, "pol-A", res.SelectedPolicyID)
}

// TestSelectPolicy_UnionAcrossPolicyGuardrails proves a policy with multiple
// allowlist guardrails permits the union of their models (not just the first).
func TestSelectPolicy_UnionAcrossPolicyGuardrails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1", "g-2")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1",
		allowlistGuardrail("g-1", "acc-1", "gpt-4o"),
		allowlistGuardrail("g-2", "acc-1", "claude-opus-4"),
	)
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "claude-opus-4", // only in the second guardrail's list
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "a model in any of the policy's allowlist guardrails must be permitted")
	assert.Equal(t, "pol-A", res.SelectedPolicyID)
}

// TestSelectPolicy_GuardrailLookupErrorPropagates proves a store failure while
// resolving the candidate policies' guardrails surfaces as an error, not a
// silent allow/deny.
func TestSelectPolicy_GuardrailLookupErrorPropagates(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	mockStore.EXPECT().
		GetAccountAgentNetworkGuardrails(gomock.Any(), gomock.Any(), "acc-1").
		Return(nil, errors.New("store unavailable"))

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "gpt-4o",
	})
	require.Error(t, err, "a guardrail-lookup failure must surface as an error")
	assert.Nil(t, res)
}

// TestSelectPolicy_MissingGuardrailReferenceTreatedAsUnrestricted proves a
// policy referencing a guardrail ID absent from the account's set (a stale
// reference) imposes no model restriction — same as no guardrail.
func TestSelectPolicy_MissingGuardrailReferenceTreatedAsUnrestricted(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-missing")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1")
	// Deliberately no provider expectation: an orphaned guardrail reference
	// restricts nothing, so the gate must skip the catalog-id lookup.
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "anything-goes",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "an orphaned guardrail reference must not restrict the model")
	assert.Equal(t, "pol-A", res.SelectedPolicyID)
}

// TestSelectPolicy_PartialCandidatesPermittedAfterModelFilter proves the model
// gate narrows candidates before cap scoring: the permitting policy is selected
// even though the blocked one has a larger, more attractive cap.
func TestSelectPolicy_PartialCandidatesPermittedAfterModelFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	polBig := guardedPolicy("pol-big", "acc-1", []string{"grp-eng"}, "prov-1", "g-restrict")
	polBig.Limits = types.PolicyLimits{
		TokenLimit: types.PolicyTokenLimit{Enabled: true, GroupCap: 1_000_000, WindowSeconds: 3600},
	}
	polSmall := guardedPolicy("pol-small", "acc-1", []string{"grp-eng"}, "prov-1", "g-permit")
	polSmall.Limits = types.PolicyLimits{
		TokenLimit: types.PolicyTokenLimit{Enabled: true, GroupCap: 100, WindowSeconds: 3600},
	}
	expectPolicies(mockStore, "acc-1", polBig, polSmall)
	expectGuardrails(mockStore, "acc-1",
		allowlistGuardrail("g-restrict", "acc-1", "gpt-4o"),
		allowlistGuardrail("g-permit", "acc-1", "claude-opus-4"),
	)
	expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "claude-opus-4", // only pol-small's guardrail permits this
	})
	require.NoError(t, err)
	assert.True(t, res.Allow)
	assert.Equal(t, "pol-small", res.SelectedPolicyID,
		"the model filter must exclude pol-big before cap scoring")
}

// TestSelectPolicy_RawDeclaredAllowlistPermitsCanonicalModel proves an
// allowlist holding the raw vendor-issued id — the form the dashboard's
// picker copies from a provider's declared models — permits the request:
// the parser emits the path-style canonical id, so the entry must match
// through the same canonicalization.
func TestSelectPolicy_RawDeclaredAllowlistPermitsCanonicalModel(t *testing.T) {
	cases := []struct {
		name    string
		catalog string
		entry   string
		request string
	}{
		{"bedrock raw region/version form", "bedrock_api", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic.claude-sonnet-4-5"},
		{"vertex raw @version form", "vertex_ai_api", "claude-sonnet-4-5@20250929", "claude-sonnet-4-5"},
		{"vertex raw dated @version form", "vertex_ai_api", "gpt-4o@2024-08-06", "gpt-4o"},
		{"bedrock raw form with case and whitespace", "bedrock_api", " EU.Anthropic.Claude-Sonnet-4-5-20250929-V1:0 ", "anthropic.claude-sonnet-4-5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mgr, mockStore := newSelectorMgr(t, ctrl)

			policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
			expectPolicies(mockStore, "acc-1", policy)
			expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", tc.entry))
			expectProviderCatalog(mockStore, "acc-1", "prov-1", tc.catalog)
			expectConsumptionBatch(mockStore, nil)

			res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
				AccountID:  "acc-1",
				UserID:     "user-1",
				GroupIDs:   []string{"grp-eng"},
				ProviderID: "prov-1",
				Model:      tc.request,
			})
			require.NoError(t, err)
			assert.True(t, res.Allow, "the raw declared allowlist entry must permit its canonical model")
			assert.Equal(t, "pol-A", res.SelectedPolicyID)
		})
	}

	// A model outside the allowlist stays denied under the same entry shape.
	t.Run("unrelated canonical model stays denied", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mgr, mockStore := newSelectorMgr(t, ctrl)

		policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
		expectPolicies(mockStore, "acc-1", policy)
		expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"))
		expectProviderCatalog(mockStore, "acc-1", "prov-1", "bedrock_api")

		res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
			AccountID:  "acc-1",
			UserID:     "user-1",
			GroupIDs:   []string{"grp-eng"},
			ProviderID: "prov-1",
			Model:      "anthropic.claude-opus-4-8",
		})
		require.NoError(t, err)
		assert.False(t, res.Allow, "a model the allowlist never names must stay denied")
		assert.Equal(t, denyCodeModelBlocked, res.DenyCode)
	})
}

// TestSelectPolicy_PlainProviderEntriesStayVerbatim proves the canonical-form
// compare never relaxes an allowlist on a body-routed provider: its catalog
// id selects no normalizer, so a suffix that would be stripped under Bedrock
// ("-v2") or Vertex ("@...") stays part of the entry and must NOT also admit
// the stripped id — on this provider that is a different model.
func TestSelectPolicy_PlainProviderEntriesStayVerbatim(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		request string
	}{
		{"a -vN suffix is not a Bedrock version tag here", "claude-3-5-sonnet-v2", "claude-3-5-sonnet"},
		{"an @word suffix is not a Vertex version tag here", "custom-model@team", "custom-model"},
		{"an @digits suffix is not a Vertex version tag here", "custom-model@2024", "custom-model"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mgr, mockStore := newSelectorMgr(t, ctrl)

			policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
			expectPolicies(mockStore, "acc-1", policy)
			expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", tc.entry))
			expectProviderCatalog(mockStore, "acc-1", "prov-1", "openai_api")

			res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
				AccountID:  "acc-1",
				UserID:     "user-1",
				GroupIDs:   []string{"grp-eng"},
				ProviderID: "prov-1",
				Model:      tc.request,
			})
			require.NoError(t, err)
			assert.False(t, res.Allow, "a plain provider's allowlist entry must not widen to its stripped form")
			assert.Equal(t, denyCodeModelBlocked, res.DenyCode)
		})
	}
}

// TestSelectPolicy_MissingProviderRecordComparesVerbatim proves a provider the
// store no longer holds degrades to the verbatim-only compare — the raw entry
// still matches itself, and nothing widens — rather than erroring or guessing
// a normalizer.
func TestSelectPolicy_MissingProviderRecordComparesVerbatim(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"))
	mockStore.EXPECT().
		GetAgentNetworkProviderByID(gomock.Any(), gomock.Any(), "acc-1", "prov-1").
		Return(nil, status.Errorf(status.NotFound, "provider not found")).
		AnyTimes()

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "anthropic.claude-sonnet-4-5",
	})
	require.NoError(t, err)
	assert.False(t, res.Allow, "without the provider record the compare runs verbatim and must not widen")
	assert.Equal(t, denyCodeModelBlocked, res.DenyCode)
}

// TestSelectPolicy_ProviderLookupErrorPropagates proves a store failure while
// resolving the provider's catalog id surfaces as an error — the model gate is
// a security decision and must not silently degrade.
func TestSelectPolicy_ProviderLookupErrorPropagates(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o"))
	mockStore.EXPECT().
		GetAgentNetworkProviderByID(gomock.Any(), gomock.Any(), "acc-1", "prov-1").
		Return(nil, errors.New("store unavailable"))

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
		Model:      "gpt-4o",
	})
	require.Error(t, err, "a provider-lookup failure must surface as an error")
	assert.Nil(t, res)
}
