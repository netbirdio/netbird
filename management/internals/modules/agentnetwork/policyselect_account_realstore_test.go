package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// GC-2 no-mock enforcement tests for the account-budget ceiling. They drive the
// real store + real consumption accounting through SelectPolicyForRequest and
// RecordAccountBudgetUsage, asserting min-wins (account binds independently of
// policy), targeting (groups + direct users), and the record fan-out.

func accountWideUserTokenRule(id string, userCap, window int64) *types.AccountBudgetRule {
	r := types.NewAccountBudgetRule(realSelectAccount)
	r.ID = id
	r.Limits.TokenLimit = types.PolicyTokenLimit{Enabled: true, UserCap: userCap, WindowSeconds: window}
	return r
}

// TestSelectPolicy_RealStore_AccountCeilingBindsEvenWithUncappedPolicy proves
// min-wins: the account user ceiling denies once exhausted even though a
// catch-all-allow (uncapped) policy would otherwise pass the request. The
// account gate runs independently of and ahead of policy selection.
func TestSelectPolicy_RealStore_AccountCeilingBindsEvenWithUncappedPolicy(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	// An uncapped (catch-all-allow) policy: enabled token limit, zero caps.
	uncapped := capPolicy("pol-open", realSelectAccount, []string{"grp-eng"}, "prov-1", 0, 86_400)
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, uncapped))

	// Account-wide user ceiling of 100 tokens in an hourly window.
	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, accountWideUserTokenRule("ainbud-1", 100, 3_600)))

	in := PolicySelectionInput{AccountID: realSelectAccount, UserID: "user-1", GroupIDs: []string{"grp-eng"}, ProviderID: "prov-1"}

	// Fresh: account ceiling has headroom, uncapped policy wins.
	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.True(t, res.Allow, "fresh account ceiling must allow")

	// Drain the account user ceiling via the fan-out path.
	require.NoError(t, mgr.RecordAccountBudgetUsage(ctx, realSelectAccount, "user-1", []string{"grp-eng"}, 100, 0, 0))

	res, err = mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.False(t, res.Allow, "account ceiling must deny even though the policy is uncapped (min-wins)")
	assert.Equal(t, denyCodeAccountTokenCapExceeded, res.DenyCode, "deny must carry the llm_account.* code")
}

// TestSelectPolicy_RealStore_AccountGroupCeiling proves a group-targeted rule
// binds the caller's group dimension.
func TestSelectPolicy_RealStore_AccountGroupCeiling(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	rule := types.NewAccountBudgetRule(realSelectAccount)
	rule.ID = "ainbud-grp"
	rule.TargetGroups = []string{"grp-eng"}
	rule.Limits.BudgetLimit = types.PolicyBudgetLimit{Enabled: true, GroupCapUsd: 5.0, WindowSeconds: 2_592_000}
	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, rule))

	in := PolicySelectionInput{AccountID: realSelectAccount, UserID: "user-1", GroupIDs: []string{"grp-eng"}, ProviderID: "prov-1"}

	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.True(t, res.Allow, "fresh group ceiling must allow")

	require.NoError(t, mgr.RecordAccountBudgetUsage(ctx, realSelectAccount, "user-1", []string{"grp-eng"}, 0, 0, 5.0))

	res, err = mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.False(t, res.Allow, "group budget ceiling must deny once spent")
	assert.Equal(t, denyCodeAccountBudgetCapExceeded, res.DenyCode, "account budget deny code")
}

// TestSelectPolicy_RealStore_AccountTargetUsersBindsOnlyThatUser proves a
// TargetUsers rule tightens only the named user, leaving others unbound.
func TestSelectPolicy_RealStore_AccountTargetUsersBindsOnlyThatUser(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	rule := types.NewAccountBudgetRule(realSelectAccount)
	rule.ID = "ainbud-alice"
	rule.TargetUsers = []string{"alice"}
	rule.Limits.TokenLimit = types.PolicyTokenLimit{Enabled: true, UserCap: 100, WindowSeconds: 3_600}
	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, rule))

	// Record alice's usage to the rule window.
	require.NoError(t, mgr.RecordAccountBudgetUsage(ctx, realSelectAccount, "alice", nil, 100, 0, 0))

	aliceIn := PolicySelectionInput{AccountID: realSelectAccount, UserID: "alice", ProviderID: "prov-1"}
	res, err := mgr.SelectPolicyForRequest(ctx, aliceIn)
	require.NoError(t, err)
	assert.False(t, res.Allow, "alice is bound by the TargetUsers rule and is exhausted")

	bobIn := PolicySelectionInput{AccountID: realSelectAccount, UserID: "bob", ProviderID: "prov-1"}
	res, err = mgr.SelectPolicyForRequest(ctx, bobIn)
	require.NoError(t, err)
	assert.True(t, res.Allow, "bob is not in TargetUsers, so the rule must not bind him")
}

// TestSelectPolicy_RealStore_AccountRuleRecordsToOwnWindow proves the record
// fan-out books usage in the rule's own window (distinct from any policy
// window), so the account ceiling accumulates independently.
func TestSelectPolicy_RealStore_AccountRuleRecordsToOwnWindow(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, accountWideUserTokenRule("ainbud-w", 100, 3_600)))

	require.NoError(t, mgr.RecordAccountBudgetUsage(ctx, realSelectAccount, "user-1", nil, 60, 0, 0))

	// Same user, a policy-style daily window must NOT see the account-window
	// usage — windows are independent counters.
	dailyRow, err := s.GetAgentNetworkConsumption(ctx, store.LockingStrengthNone, realSelectAccount, types.DimensionUser, "user-1", 86_400, types.WindowStart(time.Now().UTC(), 86_400))
	require.NoError(t, err)
	assert.Equal(t, int64(0), dailyRow.TokensInput+dailyRow.TokensOutput, "daily window must be untouched by the hourly account-rule record")

	// A second record pushes the hourly account window to its cap → deny.
	require.NoError(t, mgr.RecordAccountBudgetUsage(ctx, realSelectAccount, "user-1", nil, 40, 0, 0))
	res, err := mgr.SelectPolicyForRequest(ctx, PolicySelectionInput{AccountID: realSelectAccount, UserID: "user-1", ProviderID: "prov-1"})
	require.NoError(t, err)
	assert.False(t, res.Allow, "100 tokens recorded in the rule's hourly window must exhaust the 100-token ceiling")
	assert.Equal(t, denyCodeAccountTokenCapExceeded, res.DenyCode, "account token deny code")
}

// TestRecordUsage_RealStore_BooksPolicyAndAccountWindows proves the batched
// post-flight write books the selected policy's window AND every applicable
// account rule's (independent) window in a single call — the #6 batched-write
// path the proxy's RecordLLMUsage RPC now uses.
func TestRecordUsage_RealStore_BooksPolicyAndAccountWindows(t *testing.T) {
	mgr, s := newRealSelectorMgr(t)
	ctx := context.Background()

	// Policy: 100-token group cap on a daily window. Account rule: 100-token
	// user ceiling on an hourly window — an independent counter.
	policy := capPolicy("pol-1", realSelectAccount, []string{"grp-eng"}, "prov-1", 100, 86_400)
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))
	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, accountWideUserTokenRule("ainbud-1", 100, 3_600)))

	in := PolicySelectionInput{AccountID: realSelectAccount, UserID: "user-1", GroupIDs: []string{"grp-eng"}, ProviderID: "prov-1"}
	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	require.True(t, res.Allow)
	require.Equal(t, "pol-1", res.SelectedPolicyID)

	// One batched record books the policy window (group + user @86400) and the
	// account rule window (user @3600) atomically.
	require.NoError(t, mgr.RecordUsage(ctx, RecordUsageInput{
		AccountID:          realSelectAccount,
		UserID:             "user-1",
		AttributionGroupID: res.AttributionGroupID,
		GroupIDs:           []string{"grp-eng"},
		WindowSeconds:      res.WindowSeconds,
		TokensIn:           100,
	}))

	// The next selection denies — the account hourly ceiling binds first.
	res, err = mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	assert.False(t, res.Allow, "usage booked by RecordUsage must enforce on the next request")

	// Prove BOTH windows were booked in the one call via a direct batch read.
	now := time.Now().UTC()
	userKey := types.ConsumptionKey{Kind: types.DimensionUser, DimID: "user-1", WindowSeconds: 3_600, WindowStartUTC: types.WindowStart(now, 3_600)}
	groupKey := types.ConsumptionKey{Kind: types.DimensionGroup, DimID: "grp-eng", WindowSeconds: 86_400, WindowStartUTC: types.WindowStart(now, 86_400)}
	rows, err := s.GetAgentNetworkConsumptionBatch(ctx, store.LockingStrengthNone, realSelectAccount, []types.ConsumptionKey{userKey, groupKey})
	require.NoError(t, err)
	require.Contains(t, rows, userKey, "account rule user/hourly window booked")
	require.Contains(t, rows, groupKey, "policy group/daily window booked")
	assert.Equal(t, int64(100), rows[userKey].TokensInput, "account hourly user counter")
	assert.Equal(t, int64(100), rows[groupKey].TokensInput, "policy daily group counter")
}
