package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

// TestAgentNetworkBudgetRule_RealStore_RoundTrip is the GC-0 no-mock guard: it
// drives the budget-rule CRUD through a real sqlite store and asserts the full
// object — targets and the reused PolicyLimits cap shape — survives the
// save → gorm/JSON serialize → reload round-trip, then that delete removes it
// and a second delete reports NotFound.
func TestAgentNetworkBudgetRule_RealStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const accountID = "acc-budgetrule-1"
	rule := agentNetworkTypes.NewAccountBudgetRule(accountID)
	rule.Name = "eng-monthly"
	rule.TargetGroups = []string{"grp-eng", "grp-oncall"}
	rule.TargetUsers = []string{"user-alice"}
	rule.Limits = agentNetworkTypes.PolicyLimits{
		TokenLimit: agentNetworkTypes.PolicyTokenLimit{
			Enabled: true, GroupCap: 100_000, UserCap: 10_000, WindowSeconds: 2_592_000,
		},
		BudgetLimit: agentNetworkTypes.PolicyBudgetLimit{
			Enabled: true, GroupCapUsd: 500, UserCapUsd: 50, WindowSeconds: 2_592_000,
		},
	}
	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, rule), "save must succeed")

	got, err := s.GetAgentNetworkBudgetRuleByID(ctx, LockingStrengthNone, accountID, rule.ID)
	require.NoError(t, err, "get by id must succeed after save")
	assert.Equal(t, rule.Name, got.Name, "name must round-trip")
	assert.Equal(t, []string{"grp-eng", "grp-oncall"}, got.TargetGroups, "target groups must round-trip")
	assert.Equal(t, []string{"user-alice"}, got.TargetUsers, "target users must round-trip")
	assert.Equal(t, rule.Limits, got.Limits, "the reused PolicyLimits cap shape must round-trip intact")
	assert.True(t, got.Enabled, "enabled must round-trip")

	list, err := s.GetAccountAgentNetworkBudgetRules(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err, "list must succeed")
	require.Len(t, list, 1, "exactly the one saved rule must be listed")
	assert.Equal(t, rule.ID, list[0].ID, "listed rule id must match")

	require.NoError(t, s.DeleteAgentNetworkBudgetRule(ctx, accountID, rule.ID), "delete must succeed")

	_, err = s.GetAgentNetworkBudgetRuleByID(ctx, LockingStrengthNone, accountID, rule.ID)
	assert.Error(t, err, "get after delete must report not found")

	err = s.DeleteAgentNetworkBudgetRule(ctx, accountID, rule.ID)
	assert.Error(t, err, "deleting an absent rule must report not found")
}

// TestAgentNetworkBudgetRule_RealStore_ScopedByAccount pins that rules are
// account-scoped: a rule under one account is invisible to another.
func TestAgentNetworkBudgetRule_RealStore_ScopedByAccount(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	ruleA := agentNetworkTypes.NewAccountBudgetRule("acc-A")
	require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, ruleA))

	list, err := s.GetAccountAgentNetworkBudgetRules(ctx, LockingStrengthNone, "acc-B")
	require.NoError(t, err)
	assert.Empty(t, list, "account B must not see account A's budget rule")

	_, err = s.GetAgentNetworkBudgetRuleByID(ctx, LockingStrengthNone, "acc-B", ruleA.ID)
	assert.Error(t, err, "cross-account get by id must not resolve")
}

// TestAgentNetworkSettings_RealStore_CollectionTogglesRoundTrip pins the GC-0
// additive settings columns: the three collection toggles default off on a
// fresh row and survive a save/reload at their set values.
func TestAgentNetworkSettings_RealStore_CollectionTogglesRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	const accountID = "acc-settings-toggles"
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, &agentNetworkTypes.Settings{
		AccountID: accountID,
		Cluster:   "eu.proxy.netbird.io",
		Subdomain: "violet",
	}))

	got, err := s.GetAgentNetworkSettings(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	assert.False(t, got.EnableLogCollection, "log collection must default off")
	assert.False(t, got.EnablePromptCollection, "prompt collection must default off")
	assert.False(t, got.RedactPii, "redact pii must default off")

	got.EnableLogCollection = true
	got.EnablePromptCollection = true
	got.RedactPii = true
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, got))

	reloaded, err := s.GetAgentNetworkSettings(ctx, LockingStrengthNone, accountID)
	require.NoError(t, err)
	assert.True(t, reloaded.EnableLogCollection, "log collection must round-trip on")
	assert.True(t, reloaded.EnablePromptCollection, "prompt collection must round-trip on")
	assert.True(t, reloaded.RedactPii, "redact pii must round-trip on")
}
