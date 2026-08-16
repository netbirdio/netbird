package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

// These tests drive the effective-setup computation through the real
// sqlite store, mirroring the policyselect realstore suite: assert on
// observable answers (configured / providers / models), not on which
// store methods get called. The computation must agree with what the
// proxy enforces — policy filtering matches filterApplicablePolicies,
// model logic matches policyPermitsModel, and orphan providers are
// omitted like the router synthesizer omits them.

func newSetupTestMgr(t *testing.T) (*managerImpl, store.Store) {
	t.Helper()
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	t.Cleanup(cleanup)
	return &managerImpl{store: s}, s
}

// newSetupTestGuardrail returns an allowlist-enabled guardrail.
func newSetupTestGuardrail(id string, models ...string) *types.Guardrail {
	return &types.Guardrail{
		ID:        id,
		AccountID: testAccountID,
		Name:      "allowlist " + id,
		Checks: types.GuardrailChecks{
			ModelAllowlist: types.GuardrailModelAllowlist{Enabled: true, Models: models},
		},
	}
}

func TestEffectiveSetup_RealStore_NoSettingsRow(t *testing.T) {
	mgr, _ := newSetupTestMgr(t)

	setup, err := mgr.effectiveSetupForGroups(context.Background(), testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	assert.False(t, setup.Configured, "account without settings must read as not configured")
	assert.Empty(t, setup.Endpoint)
	assert.Empty(t, setup.Providers)
}

func TestEffectiveSetup_RealStore_NoApplicablePolicy(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-other"})
	require.NoError(t, err)
	assert.False(t, setup.Configured, "caller outside every policy's source groups must read as not configured")
	assert.Empty(t, setup.Endpoint, "no-access answer must not leak the endpoint")
	assert.Empty(t, setup.Providers)
}

func TestEffectiveSetup_RealStore_UnrestrictedPolicyListsDeclaredModels(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	assert.True(t, setup.Configured)
	assert.Equal(t, "https://"+testEndpoint, setup.Endpoint)
	require.Len(t, setup.Providers, 1)
	p := setup.Providers[0]
	assert.Equal(t, "OpenAI", p.Name)
	assert.Equal(t, "openai_api", p.CatalogID)
	assert.Equal(t, "openai", p.APIFlavor)
	assert.True(t, p.AllModelsAllowed, "policy without allowlist guardrail is unrestricted")
	assert.Equal(t, []string{"gpt-5.4"}, p.Models, "declared models listed as a courtesy")
}

func TestEffectiveSetup_RealStore_AllowlistIntersectsDeclaredModels(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	provider.Models = []types.ProviderModel{{ID: "gpt-5.4"}, {ID: "gpt-4o"}}
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	// Allowlist admits gpt-5.4 (declared, odd casing/spacing) and gpt-4.1
	// (NOT declared — the router would never route it, so it must not be
	// advertised).
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-1", " GPT-5.4 ", "gpt-4.1")))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "guard-1")))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	require.Len(t, setup.Providers, 1)
	p := setup.Providers[0]
	assert.False(t, p.AllModelsAllowed)
	assert.Equal(t, []string{"gpt-5.4"}, p.Models, "allowlist ∩ declared, in declared order and casing")
}

func TestEffectiveSetup_RealStore_UnrestrictedPolicyWinsOverRestricted(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-1", "gpt-5.4")))
	restricted := newSynthTestPolicy(provider.ID, "grp-eng", "guard-1")
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, restricted))
	open := newSynthTestPolicy(provider.ID, "grp-eng", "")
	open.ID = "pol-2"
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, open))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	require.Len(t, setup.Providers, 1)
	assert.True(t, setup.Providers[0].AllModelsAllowed,
		"one applicable policy without an allowlist makes the provider unrestricted — the proxy would admit any model through it")
}

func TestEffectiveSetup_RealStore_AllowlistUnionAcrossPolicies(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	provider.Models = []types.ProviderModel{{ID: "gpt-5.4"}, {ID: "gpt-4o"}, {ID: "o4-mini"}}
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-1", "gpt-5.4")))
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-2", "gpt-4o")))
	p1 := newSynthTestPolicy(provider.ID, "grp-eng", "guard-1")
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, p1))
	p2 := newSynthTestPolicy(provider.ID, "grp-eng", "guard-2")
	p2.ID = "pol-2"
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, p2))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	require.Len(t, setup.Providers, 1)
	p := setup.Providers[0]
	assert.False(t, p.AllModelsAllowed)
	assert.ElementsMatch(t, []string{"gpt-5.4", "gpt-4o"}, p.Models, "union of allowlists across applicable policies")
}

func TestEffectiveSetup_RealStore_OrphanAndDisabledProvidersOmitted(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	// Orphan: enabled but referenced by no policy.
	orphan := newSynthTestProvider()
	orphan.ID = "prov-orphan"
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, orphan))
	// Disabled but referenced by an applicable policy.
	disabled := newSynthTestProvider()
	disabled.ID = "prov-disabled"
	disabled.Enabled = false
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, disabled))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(disabled.ID, "grp-eng", "")))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	assert.False(t, setup.Configured, "neither an orphan nor a disabled provider is reachable, so nothing is configured for the caller")
	assert.Empty(t, setup.Providers)
}

func TestEffectiveSetup_RealStore_DisabledPolicyIgnored(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")
	policy.Enabled = false
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	assert.False(t, setup.Configured)
}

func TestEffectiveSetup_RealStore_UndeclaredModelsUseAllowlistAsIs(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	// Gateway-style provider: no declared models — the router claims every
	// model, so the allowlist union is the effective set on its own.
	provider := newSynthTestProvider()
	provider.ProviderID = "litellm_proxy"
	provider.Name = "LiteLLM"
	provider.Models = nil
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-1", "claude-sonnet-4-5")))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "guard-1")))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	require.Len(t, setup.Providers, 1)
	p := setup.Providers[0]
	assert.False(t, p.AllModelsAllowed)
	assert.Equal(t, []string{"claude-sonnet-4-5"}, p.Models)
}

func TestEffectiveSetup_RealStore_ProvidersInCreatedAtOrder(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	newer := newSynthTestProvider()
	newer.ID = "prov-newer"
	newer.Name = "Newer"
	newer.CreatedAt = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, newer))
	older := newSynthTestProvider()
	older.ID = "prov-older"
	older.Name = "Older"
	older.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, older))

	policy := newSynthTestPolicy(newer.ID, "grp-eng", "")
	policy.DestinationProviderIDs = []string{newer.ID, older.ID}
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))

	setup, err := mgr.effectiveSetupForGroups(ctx, testAccountID, []string{"grp-eng"})
	require.NoError(t, err)
	require.Len(t, setup.Providers, 2)
	assert.Equal(t, "Older", setup.Providers[0].Name)
	assert.Equal(t, "Newer", setup.Providers[1].Name)
}

// TestGetSetupForUser_RealStore pins the self-service entry point: the
// user's group memberships (AutoGroups — the same groups the user's peers
// carry) scope the answer, and users outside every policy get the
// indistinguishable not-configured shape.
func TestGetSetupForUser_RealStore(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	// users.account_id is a foreign key into accounts, enforced on
	// MySQL/Postgres, so the account row must exist before its users.
	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: testAccountID}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-in", AccountID: testAccountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{"grp-eng"},
	}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-out", AccountID: testAccountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{"grp-other"},
	}))

	setupIn, err := mgr.GetSetupForUser(ctx, testAccountID, "user-in")
	require.NoError(t, err)
	assert.True(t, setupIn.Configured)
	require.Len(t, setupIn.Providers, 1)

	setupOut, err := mgr.GetSetupForUser(ctx, testAccountID, "user-out")
	require.NoError(t, err)
	assert.False(t, setupOut.Configured, "user outside the policy's source groups gets the not-configured answer")
}

// TestListConsumptionForUser_RealStore pins the own-consumption scope: only
// the caller's user-dimension rows come back, never another user's rows or
// group rows.
func TestListConsumptionForUser_RealStore(t *testing.T) {
	mgr, s := newSetupTestMgr(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Hour)
	require.NoError(t, s.IncrementAgentNetworkConsumption(ctx, testAccountID, types.DimensionUser, "user-a", 3600, now, 100, 50, 0.5))
	require.NoError(t, s.IncrementAgentNetworkConsumption(ctx, testAccountID, types.DimensionUser, "user-b", 3600, now, 999, 999, 9.9))
	require.NoError(t, s.IncrementAgentNetworkConsumption(ctx, testAccountID, types.DimensionGroup, "grp-eng", 3600, now, 1, 1, 0.1))

	rows, err := mgr.ListConsumptionForUser(ctx, testAccountID, "user-a")
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the caller's own user-dimension rows are visible")
	assert.Equal(t, "user-a", rows[0].DimensionID)
	assert.Equal(t, int64(100), rows[0].TokensInput)
}
