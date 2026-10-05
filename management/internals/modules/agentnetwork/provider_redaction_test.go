package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// These tests pin the provider read surface per grant: a caller holding
// providers read together with update (managers) gets the full record,
// while read-only viewers (usage_viewer) get the display surface only —
// connection configuration is redacted before it reaches the wire layer.

func TestGetAllProviders_RedactsConnectionConfigForReadOnlyViewer(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	saved := newSynthTestProvider()
	saved.ExtraValues = map[string]string{"x-portkey-config": "cfg-123"}
	saved.IdentityHeaderUserID = "X-User"
	saved.IdentityHeaderGroups = "X-Groups"
	saved.SkipTLSVerification = true
	require.NoError(t, f.store.SaveAgentNetworkProvider(ctx, saved))

	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Read, true)
	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Update, false)

	providers, err := f.manager.GetAllProviders(ctx, testAccountID, "viewer")
	require.NoError(t, err)
	require.Len(t, providers, 1)
	p := providers[0]
	assert.Equal(t, saved.ID, p.ID, "identity survives redaction")
	assert.Equal(t, saved.Name, p.Name)
	assert.Equal(t, saved.ProviderID, p.ProviderID)
	assert.Equal(t, saved.Models, p.Models, "the model list backs the usage filters and stays")
	assert.True(t, p.Enabled)
	assert.Empty(t, p.UpstreamURL, "upstream URL is connection config")
	assert.Empty(t, p.ExtraValues, "operator-typed header values are connection config")
	assert.Empty(t, p.IdentityHeaderUserID)
	assert.Empty(t, p.IdentityHeaderGroups)
	assert.False(t, p.SkipTLSVerification)
	assert.Empty(t, p.APIKey)
	assert.Empty(t, p.SessionPrivateKey)

	stored, err := f.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, testAccountID, saved.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, stored.UpstreamURL, "redaction must not write back to the store")
}

func TestGetProvider_FullConfigForManagingCaller(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	saved := newSynthTestProvider()
	saved.ExtraValues = map[string]string{"x-portkey-config": "cfg-123"}
	require.NoError(t, f.store.SaveAgentNetworkProvider(ctx, saved))

	f.expectPermission(testAccountID, "admin", modules.AgentNetworkProviders, operations.Read, true)
	f.expectPermission(testAccountID, "admin", modules.AgentNetworkProviders, operations.Update, true)

	p, err := f.manager.GetProvider(ctx, testAccountID, "admin", saved.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.UpstreamURL, p.UpstreamURL, "a caller who can edit the provider sees its config")
	assert.Equal(t, saved.ExtraValues, p.ExtraValues)
}

func TestGetProvider_RedactsForReadOnlyViewer(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	saved := newSynthTestProvider()
	require.NoError(t, f.store.SaveAgentNetworkProvider(ctx, saved))

	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Read, true)
	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Update, false)

	p, err := f.manager.GetProvider(ctx, testAccountID, "viewer", saved.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.ID, p.ID)
	assert.Empty(t, p.UpstreamURL)
}

// The self-scope tests drive the real permissions manager over the real
// store, so role resolution is the production one: a plain user holds no
// providers grant and must fall back to the caller-scoped list — the same
// selection the self-service setup answer derives from — while an admin
// keeps the account-wide view with full config.

// newSelfScopeStore seeds the account and its users only, so each test
// declares exactly the providers and policies it asserts on — the store
// rejects re-saving a policy id on MySQL, so tests never overwrite each
// other's rows.
func newSelfScopeStore(t *testing.T) (*managerImpl, store.Store) {
	t.Helper()
	mgr, s := newAgentConfigTestMgr(t)
	mgr.permissionsManager = permissions.NewManager(s)
	ctx := context.Background()

	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: testAccountID}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-a", AccountID: testAccountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{"grp-eng"},
	}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-out", AccountID: testAccountID, Role: nbtypes.UserRoleUser,
	}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "admin", AccountID: testAccountID, Role: nbtypes.UserRoleAdmin,
	}))
	return mgr, s
}

func newSelfScopeProvidersFixture(t *testing.T) (*managerImpl, store.Store) {
	t.Helper()
	mgr, s := newSelfScopeStore(t)
	ctx := context.Background()

	granted := newSynthTestProvider()
	granted.ID = "prov-granted"
	granted.Name = "Granted"
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, granted))

	other := newSynthTestProvider()
	other.ID = "prov-other"
	other.Name = "Other"
	other.CreatedAt = granted.CreatedAt.Add(time.Hour)
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, other))

	disabled := newSynthTestProvider()
	disabled.ID = "prov-disabled"
	disabled.Name = "Disabled"
	disabled.Enabled = false
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, disabled))

	// user-a's group authorizes the granted and the disabled provider; the
	// disabled one must still not surface (the proxy never routes it).
	policy := newSynthTestPolicy(granted.ID, "grp-eng", "")
	policy.DestinationProviderIDs = []string{granted.ID, disabled.ID}
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))

	return mgr, s
}

func TestGetAllProviders_SelfScopedForPlainUser(t *testing.T) {
	ctx := context.Background()
	mgr, _ := newSelfScopeProvidersFixture(t)

	scoped, err := mgr.GetAllProviders(ctx, testAccountID, "user-a")
	require.NoError(t, err, "a caller without the read grant self-scopes instead of being denied")
	require.Len(t, scoped, 1)
	assert.Equal(t, "prov-granted", scoped[0].ID)
	assert.Empty(t, scoped[0].UpstreamURL, "the caller-scoped list is the redacted display surface")
	assert.NotEmpty(t, scoped[0].Models, "model list backs the dashboard filters")

	empty, err := mgr.GetAllProviders(ctx, testAccountID, "user-out")
	require.NoError(t, err)
	assert.Empty(t, empty, "a caller outside every policy gets an empty list, not an error")

	all, err := mgr.GetAllProviders(ctx, testAccountID, "admin")
	require.NoError(t, err)
	assert.Len(t, all, 3, "grant holders keep the account-wide list, disabled providers included")
	for _, p := range all {
		if p.ID == "prov-granted" {
			assert.NotEmpty(t, p.UpstreamURL, "a managing caller sees the connection config")
		}
	}
}

func TestGetProvider_SelfScopedForPlainUser(t *testing.T) {
	ctx := context.Background()
	mgr, _ := newSelfScopeProvidersFixture(t)

	p, err := mgr.GetProvider(ctx, testAccountID, "user-a", "prov-granted")
	require.NoError(t, err)
	assert.Equal(t, "prov-granted", p.ID)
	assert.Empty(t, p.UpstreamURL)

	assertNotFound := func(id string) {
		t.Helper()
		_, err := mgr.GetProvider(ctx, testAccountID, "user-a", id)
		require.Error(t, err)
		var sErr *status.Error
		require.ErrorAs(t, err, &sErr)
		assert.Equal(t, status.NotFound, sErr.Type(),
			"out-of-scope and nonexistent providers must be indistinguishable")
	}
	assertNotFound("prov-other")
	assertNotFound("prov-disabled")
	assertNotFound("prov-does-not-exist")
}

func TestGetAllProviders_SelfScopedModelsFollowGuardrails(t *testing.T) {
	ctx := context.Background()
	mgr, s := newSelfScopeStore(t)

	// A provider declaring two models, restricted by an allowlist admitting
	// one declared model plus one the operator never declared (unreachable —
	// the router only claims declared models, so it must not surface).
	granted := newSynthTestProvider()
	granted.ID = "prov-models"
	granted.Name = "Granted"
	granted.Models = []types.ProviderModel{
		{ID: "gpt-5.4", InputPer1k: 0.004, OutputPer1k: 0.02},
		{ID: "gpt-4o", InputPer1k: 0.0025, OutputPer1k: 0.01},
	}
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, granted))
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-models", "gpt-5.4", "gpt-undeclared")))
	policy := newSynthTestPolicy(granted.ID, "grp-eng", "guard-models")
	policy.ID = "pol-guard-models"
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))

	scoped, err := mgr.GetAllProviders(ctx, testAccountID, "user-a")
	require.NoError(t, err)
	require.Len(t, scoped, 1)
	require.Len(t, scoped[0].Models, 1,
		"the self-scoped model list is the effective set: allowlist ∩ declared")
	assert.Equal(t, "gpt-5.4", scoped[0].Models[0].ID)
	assert.Equal(t, 0.004, scoped[0].Models[0].InputPer1k, "declared entry survives, prices included")

	all, err := mgr.GetAllProviders(ctx, testAccountID, "admin")
	require.NoError(t, err)
	for _, p := range all {
		if p.ID == granted.ID {
			assert.Len(t, p.Models, 2,
				"grant holders keep the full declared list — their usage view spans everyone's requests")
		}
	}
}

func TestGetAllProviders_SelfScopedAllowlistWithoutDeclaredModels(t *testing.T) {
	ctx := context.Background()
	mgr, s := newSelfScopeStore(t)

	// No operator declaration: the router claims every model, so the
	// allowlist union is the effective set and comes back as bare entries.
	granted := newSynthTestProvider()
	granted.ID = "prov-bare"
	granted.Name = "Granted"
	granted.Models = nil
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, granted))
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, newSetupTestGuardrail("guard-bare", "gpt-5.4")))
	policy := newSynthTestPolicy(granted.ID, "grp-eng", "guard-bare")
	policy.ID = "pol-guard-bare"
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))

	scoped, err := mgr.GetAllProviders(ctx, testAccountID, "user-a")
	require.NoError(t, err)
	require.Len(t, scoped, 1)
	require.Len(t, scoped[0].Models, 1)
	assert.Equal(t, "gpt-5.4", scoped[0].Models[0].ID)
}

func TestGetAllProviders_SelfScopedUnrestrictedFallsBackToCatalogModels(t *testing.T) {
	ctx := context.Background()
	mgr, s := newSelfScopeStore(t)

	// Unrestricted policy on a provider without an operator declaration:
	// the setup answer advertises the catalog models, and the scoped
	// provider list must match so the model filter is never emptier than
	// the setup page.
	granted := newSynthTestProvider()
	granted.ID = "prov-catalog"
	granted.Name = "Granted"
	granted.Models = nil
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, granted))
	policy := newSynthTestPolicy(granted.ID, "grp-eng", "")
	policy.ID = "pol-catalog"
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, policy))

	scoped, err := mgr.GetAllProviders(ctx, testAccountID, "user-a")
	require.NoError(t, err)
	require.Len(t, scoped, 1)
	require.NotEmpty(t, scoped[0].Models, "catalog models back the filter when the operator declared none")
	ids := make([]string, 0, len(scoped[0].Models))
	for _, m := range scoped[0].Models {
		ids = append(ids, m.ID)
	}
	assert.Equal(t, declaredModelIDs(granted), ids, "the scoped list mirrors the setup answer's declared/catalog set")
}
