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
// preserving the immutable Domain/ProxyAddress assigned at bootstrap. The
// request echoes the identity fields back — the PUT convention every other
// endpoint follows — and a request echoing anything else is rejected outright
// rather than quietly ignored.
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
		AccountID:  accountID,
		ProviderID: "openai_api",
		Name:       "openai",
		// A private address: the save-time credential check leaves it
		// unchecked rather than spending a dummy key against the real
		// api.openai.com, which the vendor refuses and which would make
		// this test depend on the runner having egress.
		UpstreamURL: "https://10.255.255.1",
		APIKey:      "sk-test",
		Enabled:     true,
		Models:      []agenttypes.ProviderModel{{ID: "gpt-5.4"}},
	})
	require.NoError(t, err, "CreateProvider must succeed")

	// Flipping the toggles works when the request echoes the assigned
	// identity. Retention is echoed too: UpdateSettings takes it verbatim, so
	// omitting it would zero the account's retention.
	updated, err := mgr.UpdateSettings(ctx, adminUserID, &agenttypes.Settings{
		AccountID:              accountID,
		Domain:                 before.Domain,
		ProxyAddress:           before.ProxyAddress,
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		RedactPii:              true,
		AccessLogRetentionDays: before.AccessLogRetentionDays,
	})
	require.NoError(t, err, "UpdateSettings must succeed")
	assert.Equal(t, before.Domain, updated.Domain, "domain is immutable and must be preserved")
	assert.Equal(t, before.ProxyAddress, updated.ProxyAddress, "proxy address is immutable and must be preserved")
	assert.True(t, updated.EnableLogCollection, "log collection toggle must apply")
	assert.True(t, updated.EnablePromptCollection, "prompt collection toggle must apply")
	assert.True(t, updated.RedactPii, "redact toggle must apply")
	assert.Equal(t, before.AccessLogRetentionDays, updated.AccessLogRetentionDays, "echoed retention must survive")

	// Neither identity field can be smuggled into the row: a hand-rolled
	// Settings value carrying a different endpoint or proxy address is
	// rejected, not silently ignored.
	for _, tc := range []struct {
		name         string
		domain       string
		proxyAddress string
	}{
		{name: "foreign endpoint", domain: "evil.example.com", proxyAddress: before.ProxyAddress},
		{name: "foreign proxy address", domain: before.Domain, proxyAddress: "attacker.cluster"},
		{name: "empty identity echo", domain: "", proxyAddress: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mgr.UpdateSettings(ctx, adminUserID, &agenttypes.Settings{
				AccountID:              accountID,
				Domain:                 tc.domain,
				ProxyAddress:           tc.proxyAddress,
				EnableLogCollection:    false,
				EnablePromptCollection: false,
				RedactPii:              false,
				AccessLogRetentionDays: before.AccessLogRetentionDays,
			})
			assert.Error(t, err, "a mismatched identity echo must be rejected")
			assert.ErrorContains(t, err, "immutable", "the rejection must name the immutability rule")
		})
	}

	// The rejected updates left the row exactly as the accepted one wrote it.
	afterRejects, err := mgr.GetSettings(ctx, accountID, adminUserID)
	require.NoError(t, err, "GetSettings must succeed")
	assert.True(t, afterRejects.EnablePromptCollection, "a rejected update must not roll back the accepted toggles")

	reloaded, err := am.Store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	assert.Equal(t, before.Domain, reloaded.Domain, "persisted domain unchanged")
	assert.Equal(t, before.ProxyAddress, reloaded.ProxyAddress, "persisted proxy address unchanged")
	assert.True(t, reloaded.EnablePromptCollection, "persisted prompt collection toggled on")
}
