package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
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

// TestSelectPolicy_ModelBlockedByAllowlist proves the authoritative allowlist
// decision: a policy authorises the (provider, group) but restricts the model,
// and the requested model isn't on the list, so the request is denied.
func TestSelectPolicy_ModelBlockedByAllowlist(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := guardedPolicy("pol-A", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	expectPolicies(mockStore, "acc-1", policy)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o"))

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

// TestSelectPolicy_UnguardedPolicyIsUnrestricted is the false-deny fix: when
// two policies authorise the same (provider, group) and one carries no
// guardrail, that un-guardrailed policy makes the request unrestricted — it is
// NOT caught by the other policy's allowlist.
func TestSelectPolicy_UnguardedPolicyIsUnrestricted(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	restricted := guardedPolicy("pol-restricted", "acc-1", []string{"grp-eng"}, "prov-1", "g-1")
	open := guardedPolicy("pol-open", "acc-1", []string{"grp-eng"}, "prov-1") // no guardrail
	expectPolicies(mockStore, "acc-1", restricted, open)
	expectGuardrails(mockStore, "acc-1", allowlistGuardrail("g-1", "acc-1", "gpt-4o"))
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
// model allowlisted only for grp-b must not be usable by a caller in grp-a,
// even though both groups' policies target the same provider. The selector only
// considers policies applicable to the caller's groups, so grp-b's allowlist
// never enters grp-a's decision.
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
