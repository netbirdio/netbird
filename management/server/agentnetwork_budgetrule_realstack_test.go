package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agenttypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
)

// TestAgentNetwork_BudgetRuleCRUD_RealManager is the GC-1 no-mock guard for the
// account budget-rule manager surface: real DefaultAccountManager, real store,
// real permissions. It exercises create/get/list/update/delete through the
// permission-gated manager (not the store directly) and asserts the reused
// PolicyLimits cap shape and targets survive each step.
func TestAgentNetwork_BudgetRuleCRUD_RealManager(t *testing.T) {
	am, _, err := createManager(t)
	require.NoError(t, err, "createManager must succeed")
	ctx := context.Background()

	const (
		accountID   = "agent-net-budget-acct"
		adminUserID = "agent-net-budget-admin"
	)
	account := newAccountWithId(ctx, accountID, adminUserID, "agent-net.test", "", "", false)
	require.NoError(t, am.Store.SaveAccount(ctx, account), "SaveAccount must succeed")

	mgr := agentnetwork.NewManager(am.Store, permissions.NewManager(am.Store), am, nil)

	created, err := mgr.CreateBudgetRule(ctx, adminUserID, &agenttypes.AccountBudgetRule{
		AccountID:    accountID,
		Name:         "eng-monthly",
		Enabled:      true,
		TargetGroups: []string{"grp-eng"},
		TargetUsers:  []string{"user-alice"},
		Limits: agenttypes.PolicyLimits{
			TokenLimit:  agenttypes.PolicyTokenLimit{Enabled: true, GroupCap: 100_000, UserCap: 10_000, WindowSeconds: 2_592_000},
			BudgetLimit: agenttypes.PolicyBudgetLimit{Enabled: true, GroupCapUsd: 500, WindowSeconds: 2_592_000},
		},
	})
	require.NoError(t, err, "CreateBudgetRule must succeed")
	require.NotEmpty(t, created.ID, "create must mint an ID")

	got, err := mgr.GetBudgetRule(ctx, accountID, adminUserID, created.ID)
	require.NoError(t, err, "GetBudgetRule must succeed")
	assert.Equal(t, "eng-monthly", got.Name, "name round-trips through the manager")
	assert.Equal(t, []string{"grp-eng"}, got.TargetGroups, "target groups round-trip")
	assert.Equal(t, int64(100_000), got.Limits.TokenLimit.GroupCap, "token group cap round-trips")

	list, err := mgr.GetAllBudgetRules(ctx, accountID, adminUserID)
	require.NoError(t, err, "GetAllBudgetRules must succeed")
	require.Len(t, list, 1, "exactly the one created rule must be listed")

	created.Limits.TokenLimit.GroupCap = 200_000
	updated, err := mgr.UpdateBudgetRule(ctx, adminUserID, created)
	require.NoError(t, err, "UpdateBudgetRule must succeed")
	assert.Equal(t, int64(200_000), updated.Limits.TokenLimit.GroupCap, "updated cap must persist")

	require.NoError(t, mgr.DeleteBudgetRule(ctx, accountID, adminUserID, created.ID), "DeleteBudgetRule must succeed")
	_, err = mgr.GetBudgetRule(ctx, accountID, adminUserID, created.ID)
	assert.Error(t, err, "get after delete must fail")
}

// TestAgentNetwork_UpdateSettings_PreservesImmutableAndTogglesCollection is the
// GC-1 guard for UpdateSettings: it must apply the collection toggles while
// preserving the immutable Domain/ProxyAddress assigned at bootstrap — the
// identity fields are not part of the update surface at all.
func TestAgentNetwork_UpdateSettings_PreservesImmutableAndTogglesCollection(t *testing.T) {
	am, _, err := createManager(t)
	require.NoError(t, err, "createManager must succeed")
	ctx := context.Background()

	const (
		accountID   = "agent-net-settings-acct"
		adminUserID = "agent-net-settings-admin"
		clusterAddr = "eu.proxy.netbird.io"
	)
	account := newAccountWithId(ctx, accountID, adminUserID, "agent-net.test", "", "", false)
	require.NoError(t, am.Store.SaveAccount(ctx, account), "SaveAccount must succeed")

	mgr := agentnetwork.NewManager(am.Store, permissions.NewManager(am.Store), am, nil)

	// Bootstrap is an explicit settings create; providers have no settings
	// side effects anymore.
	before, err := mgr.CreateSettings(ctx, adminUserID, agenttypes.DefaultSettings(accountID), clusterAddr, "")
	require.NoError(t, err, "CreateSettings must bootstrap the row")
	require.Equal(t, clusterAddr, before.ProxyAddress, "proxy address pinned at bootstrap")
	require.NotEmpty(t, before.Domain, "endpoint allocated at bootstrap")
	assert.False(t, before.EnablePromptCollection, "prompt collection defaults off")

	_, err = mgr.CreateProvider(ctx, adminUserID, &agenttypes.Provider{
		AccountID:   accountID,
		ProviderID:  "openai_api",
		Name:        "openai",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-test",
		Enabled:     true,
		Models:      []agenttypes.ProviderModel{{ID: "gpt-5.4"}},
	})
	require.NoError(t, err, "CreateProvider must succeed")

	// Flipping the toggles works; identity fields set on the request value
	// are ignored by FromAPIRequest/UpdateSettings by construction, but even
	// a hand-rolled Settings value cannot smuggle them into the row.
	updated, err := mgr.UpdateSettings(ctx, adminUserID, &agenttypes.Settings{
		AccountID:              accountID,
		Domain:                 "evil.example.com",
		ProxyAddress:           "attacker.cluster",
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		RedactPii:              true,
	})
	require.NoError(t, err, "UpdateSettings must succeed")
	assert.Equal(t, before.Domain, updated.Domain, "domain is immutable and must be preserved")
	assert.Equal(t, before.ProxyAddress, updated.ProxyAddress, "proxy address is immutable and must be preserved")
	assert.True(t, updated.EnableLogCollection, "log collection toggle must apply")
	assert.True(t, updated.EnablePromptCollection, "prompt collection toggle must apply")
	assert.True(t, updated.RedactPii, "redact toggle must apply")

	reloaded, err := am.Store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	assert.Equal(t, before.Domain, reloaded.Domain, "persisted domain unchanged")
	assert.Equal(t, before.ProxyAddress, reloaded.ProxyAddress, "persisted proxy address unchanged")
	assert.True(t, reloaded.EnablePromptCollection, "persisted prompt collection toggled on")
}
