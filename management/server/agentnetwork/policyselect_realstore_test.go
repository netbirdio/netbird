package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// This file is the no-mock regression guard for policy limit enforcement.
// policyselect_test.go pins the same behavior through a gomock store with
// explicit call-sequence expectations — brittle precisely where the upcoming
// account-budget work (GC-2) refactors the cap-eval primitive and adds an
// account-level gate. These tests drive the REAL sqlite store + REAL
// consumption accounting and assert observable behavior (allow / deny /
// selection / attribution), not which store methods get called. They must keep
// passing unchanged after GC-2 lands, which is what proves "current behavior is
// not changed."

const realSelectAccount = "acc-realselect-1"

// newRealSelectorMgr builds a managerImpl backed by a real sqlite test store.
func newRealSelectorMgr(t *testing.T) (*managerImpl, store.Store) {
	t.Helper()
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	t.Cleanup(cleanup)
	return &managerImpl{store: s}, s
}

// TestSelectPolicy_RealStore_NoApplicablePolicies pins the pass-through:
// nothing targets the (provider, groups) combination, so the selector allows
// without attribution or consumption tracking.
func TestSelectPolicy_RealStore_NoApplicablePolicies(t *testing.T) {
	mgr, _ := newRealSelectorMgr(t)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  realSelectAccount,
		UserID:     "user-1",
		GroupIDs:   []string{"grp-x"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "no applicable policy must pass through as allow")
	assert.Empty(t, res.SelectedPolicyID, "no selection when nothing applies")
}

// TestSelectPolicy_RealStore_AllowAndLowestGroupAttribution pins the v1
// attribution rule (lowest intersecting group by string sort) through the
// real store, with a fresh (zero) consumption row.
func TestSelectPolicy_RealStore_AllowAndLowestGroupAttribution(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	p := capPolicy("pol-A", realSelectAccount, []string{"grp-zz", "grp-aa", "grp-mm"}, "prov-1", 10_000, 86_400)
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, p))

	res, err := mgr.SelectPolicyForRequest(ctx, PolicySelectionInput{
		AccountID:  realSelectAccount,
		UserID:     "user-1",
		GroupIDs:   []string{"grp-zz", "grp-aa", "grp-mm"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "fresh state under cap must allow")
	assert.Equal(t, "pol-A", res.SelectedPolicyID, "only applicable policy must be selected")
	assert.Equal(t, "grp-aa", res.AttributionGroupID, "lowest-by-sort intersecting group must win")
	assert.Equal(t, int64(86_400), res.WindowSeconds, "selected policy's window must be returned")
}

// TestSelectPolicy_RealStore_LargerPoolWins_FallsThroughWhenExhausted pins the
// core selection behavior end to end. The two policies bind DISTINCT groups so
// they read separate counters — the only shape where fall-through actually
// yields headroom (policies on the same group share one counter, as
// policyselect_test.go notes). Larger pool wins fresh; after real consumption
// drains the larger group, selection falls through to the smaller; once both
// counters are exhausted the request is denied.
func TestSelectPolicy_RealStore_LargerPoolWins_FallsThroughWhenExhausted(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	tight := capPolicy("pol-tight", realSelectAccount, []string{"grp-tight"}, "prov-1", 100, 86_400)
	tight.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wide := capPolicy("pol-wide", realSelectAccount, []string{"grp-wide"}, "prov-1", 10_000, 86_400)
	wide.CreatedAt = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, tight))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, wide))

	// Caller is in both groups, so both policies apply with independent counters.
	in := PolicySelectionInput{
		AccountID:  realSelectAccount,
		UserID:     "user-1",
		GroupIDs:   []string{"grp-tight", "grp-wide"},
		ProviderID: "prov-1",
	}

	// Fresh: larger pool wins.
	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, "pol-wide", res.SelectedPolicyID, "larger pool drains first")

	// Drain only the wide group's counter to its cap.
	require.NoError(t, mgr.RecordConsumption(ctx, realSelectAccount, types.DimensionGroup, "grp-wide", 86_400, 10_000, 0, 0))

	// Wide exhausted, tight's separate counter is fresh → fall through to tight.
	res, err = mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.True(t, res.Allow, "tight pool has its own untouched counter")
	assert.Equal(t, "pol-tight", res.SelectedPolicyID, "selection falls through to the smaller pool once the larger is exhausted")

	// Drain the tight group's counter too → both exhausted → deny.
	require.NoError(t, mgr.RecordConsumption(ctx, realSelectAccount, types.DimensionGroup, "grp-tight", 86_400, 100, 0, 0))
	res, err = mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.False(t, res.Allow, "both group counters exhausted must deny")
	assert.Equal(t, denyCodeTokenCapExceeded, res.DenyCode, "deny code names the offending cap kind")
}

// TestSelectPolicy_RealStore_BudgetCapDenies pins budget (USD) enforcement
// through the real store: once recorded cost reaches the cap, deny.
func TestSelectPolicy_RealStore_BudgetCapDenies(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	p := &types.Policy{
		ID:                     "pol-budget",
		AccountID:              realSelectAccount,
		Enabled:                true,
		SourceGroups:           []string{"grp-eng"},
		DestinationProviderIDs: []string{"prov-1"},
		Limits: types.PolicyLimits{
			BudgetLimit: types.PolicyBudgetLimit{
				Enabled:       true,
				GroupCapUsd:   5.0,
				WindowSeconds: 86_400,
			},
		},
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, p))

	in := PolicySelectionInput{
		AccountID:  realSelectAccount,
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
	}

	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.True(t, res.Allow, "fresh budget must allow")

	require.NoError(t, mgr.RecordConsumption(ctx, realSelectAccount, types.DimensionGroup, "grp-eng", 86_400, 0, 0, 5.0))

	res, err = mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.False(t, res.Allow, "cost at the cap must deny")
	assert.Equal(t, denyCodeBudgetCapExceeded, res.DenyCode, "budget deny code must be surfaced")
}

// TestSelectPolicy_RealStore_GroupCounterSharedAcrossPolicies pins that two
// policies on the same group+window read one shared consumption counter: usage
// recorded once is visible to both, so exhausting the group budget denies
// regardless of which policy would attribute.
func TestSelectPolicy_RealStore_GroupCounterSharedAcrossPolicies(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	a := capPolicy("pol-a", realSelectAccount, []string{"grp-eng"}, "prov-1", 1_000, 86_400)
	b := capPolicy("pol-b", realSelectAccount, []string{"grp-eng"}, "prov-1", 1_000, 86_400)
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, a))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, b))

	in := PolicySelectionInput{
		AccountID:  realSelectAccount,
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
	}

	require.NoError(t, mgr.RecordConsumption(ctx, realSelectAccount, types.DimensionGroup, "grp-eng", 86_400, 1_000, 0, 0))

	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.False(t, res.Allow, "shared group counter at cap denies both equal policies")
	assert.Equal(t, denyCodeTokenCapExceeded, res.DenyCode, "token deny code on the shared counter")
}

// TestSelectPolicy_RealStore_DisabledPolicyIgnored pins that a disabled policy
// is invisible to selection even when it otherwise matches.
func TestSelectPolicy_RealStore_DisabledPolicyIgnored(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	p := capPolicy("pol-disabled", realSelectAccount, []string{"grp-eng"}, "prov-1", 10_000, 86_400)
	p.Enabled = false
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, p))

	res, err := mgr.SelectPolicyForRequest(ctx, PolicySelectionInput{
		AccountID:  realSelectAccount,
		UserID:     "user-1",
		GroupIDs:   []string{"grp-eng"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "no enabled policy applies → pass-through allow")
	assert.Empty(t, res.SelectedPolicyID, "disabled policy must not be selected")
}
