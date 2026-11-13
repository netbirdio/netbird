package agentnetwork

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

// The allowance fixture puts peer-1 (owned by user-1) in grp-eng and grp-ops,
// while user-1's auto-groups hold only grp-auto. The proxy evaluates caps
// against the peer's groups, so every group-scoped limit must come from
// grp-eng/grp-ops and nothing may come from grp-auto.
const (
	allowPeer = "peer-1"
	allowUser = "user-1"
)

var allowPeerGroups = []string{"grp-eng", "grp-ops"}

func allowanceFixture(t *testing.T, policies []*types.Policy, rules ...*types.AccountBudgetRule) (*managerImpl, store.Store) {
	t.Helper()
	mgr, s := newAgentConfigTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: testAccountID}))
	for id, name := range map[string]string{"grp-eng": "Engineering", "grp-ops": "Operations", "grp-auto": "Auto"} {
		require.NoError(t, s.CreateGroup(ctx, &nbtypes.Group{ID: id, AccountID: testAccountID, Name: name}))
	}
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, newSynthTestProvider()))
	for _, p := range policies {
		require.NoError(t, s.SaveAgentNetworkPolicy(ctx, p))
	}
	for _, r := range rules {
		require.NoError(t, s.SaveAgentNetworkBudgetRule(ctx, r))
	}

	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: allowUser, AccountID: testAccountID, Role: nbtypes.UserRoleUser,
		Email: "user-1@example.com", AutoGroups: []string{"grp-auto"},
	}))
	require.NoError(t, s.AddPeerToAccount(ctx, &nbpeer.Peer{
		ID: allowPeer, AccountID: testAccountID, UserID: allowUser, Key: "key-" + allowPeer,
		DNSLabel: allowPeer, IP: netip.AddrFrom4([4]byte{100, 64, 0, 1}), Status: &nbpeer.PeerStatus{},
	}))
	for _, g := range allowPeerGroups {
		require.NoError(t, s.AddPeerToGroup(ctx, testAccountID, allowPeer, g))
	}
	return mgr, s
}

func allowPolicy(id string, groups []string, limits types.PolicyLimits) *types.Policy {
	return &types.Policy{
		ID: id, AccountID: testAccountID, Name: "policy " + id, Enabled: true,
		SourceGroups: groups, DestinationProviderIDs: []string{"prov-1"}, Limits: limits,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func allowRule(id string, groups, users []string, limits types.PolicyLimits) *types.AccountBudgetRule {
	r := types.NewAccountBudgetRule(testAccountID)
	r.ID, r.Name, r.TargetGroups, r.TargetUsers, r.Limits = id, "rule "+id, groups, users, limits
	return r
}

func tokenLimits(userCap, groupCap, window int64) types.PolicyLimits {
	return types.PolicyLimits{TokenLimit: types.PolicyTokenLimit{Enabled: true, UserCap: userCap, GroupCap: groupCap, WindowSeconds: window}}
}

func budgetLimits(userCap, groupCap float64, window int64) types.PolicyLimits {
	return types.PolicyLimits{BudgetLimit: types.PolicyBudgetLimit{Enabled: true, UserCapUsd: userCap, GroupCapUsd: groupCap, WindowSeconds: window}}
}

// selectionInput is what the proxy sends for peer-1: the owner as principal
// and the peer's own groups.
func selectionInput() PolicySelectionInput {
	return PolicySelectionInput{AccountID: testAccountID, UserID: allowUser, GroupIDs: allowPeerGroups, ProviderID: "prov-1", Model: "gpt-5.4"}
}

// spend books usage the way the proxy does: select, then record against the
// selection.
func spend(t *testing.T, mgr *managerImpl, tokens int64, usd float64) {
	t.Helper()
	ctx := context.Background()
	in := selectionInput()
	res, err := mgr.SelectPolicyForRequest(ctx, in)
	require.NoError(t, err)
	require.NoError(t, mgr.RecordUsage(ctx, RecordUsageInput{
		AccountID: in.AccountID, UserID: in.UserID, GroupIDs: in.GroupIDs,
		AttributionGroupID: res.AttributionGroupID, WindowSeconds: res.WindowSeconds,
		TokensIn: tokens, CostUSD: usd,
	}))
}

func peerAllowance(t *testing.T, mgr *managerImpl) *types.ProviderAllowance {
	t.Helper()
	info, err := mgr.GetAgentNetworkInfoForPeer(context.Background(), testAccountID, allowPeer)
	require.NoError(t, err)
	require.Equal(t, types.PeerAgentNetworkOK, info.State)
	require.NotNil(t, info.Config)
	require.Len(t, info.Config.Providers, 1)
	require.NotNil(t, info.Config.Providers[0].Allowance, "peer answer must carry the allowance")
	return info.Config.Providers[0].Allowance
}

func TestAllowance_RealStore_PolicyUserCap(t *testing.T) {
	mgr, _ := allowanceFixture(t, []*types.Policy{allowPolicy("pol-user", []string{"grp-eng"}, tokenLimits(1000, 0, 3600))})
	spend(t, mgr, 300, 0)

	a := peerAllowance(t, mgr)
	assert.False(t, a.Unlimited, "a capped policy is not unlimited")
	assert.False(t, a.Exhausted, "300 of 1000 used")
	require.Len(t, a.Limits, 1)
	l := a.Limits[0]
	assert.Equal(t, types.AllowanceSourcePolicy, l.Source)
	assert.Equal(t, "pol-user", l.SourceID)
	assert.Equal(t, "policy pol-user", l.SourceName)
	assert.Equal(t, types.AllowanceUnitTokens, l.Unit)
	assert.Equal(t, types.AllowanceScopeUser, l.Scope)
	assert.Empty(t, l.GroupID, "user scope has no group")
	assert.Equal(t, 1000.0, l.Cap)
	assert.Equal(t, 300.0, l.Used)
	assert.Equal(t, types.WindowStart(time.Now(), 3600).Add(time.Hour), l.ResetsAt, "resets at the end of the epoch-aligned window")
}

func TestAllowance_RealStore_PolicyGroupCap(t *testing.T) {
	mgr, _ := allowanceFixture(t, []*types.Policy{allowPolicy("pol-grp", []string{"grp-ops", "grp-eng"}, budgetLimits(0, 5, 86400))})
	spend(t, mgr, 0, 1.25)

	a := peerAllowance(t, mgr)
	require.Len(t, a.Limits, 1)
	l := a.Limits[0]
	assert.Equal(t, types.AllowanceUnitUSD, l.Unit)
	assert.Equal(t, types.AllowanceScopeGroup, l.Scope)
	assert.Equal(t, "grp-eng", l.GroupID, "group caps attribute to the lowest intersecting group")
	assert.Equal(t, "Engineering", l.GroupName)
	assert.Equal(t, 5.0, l.Cap)
	assert.InDelta(t, 1.25, l.Used, 1e-9)
	assert.False(t, a.Exhausted)
}

func TestAllowance_RealStore_AccountRuleMinWins(t *testing.T) {
	// The policy allows 1000 tokens, the account rule only 100: both are
	// listed, and the rule exhausts the provider first.
	mgr, _ := allowanceFixture(t,
		[]*types.Policy{allowPolicy("pol-user", []string{"grp-eng"}, tokenLimits(1000, 0, 3600))},
		allowRule("rule-1", nil, nil, tokenLimits(100, 0, 2_592_000)),
	)

	a := peerAllowance(t, mgr)
	require.Len(t, a.Limits, 2, "rule and policy caps are both shown")
	assert.Equal(t, types.AllowanceSourceAccountRule, a.Limits[0].Source)
	assert.Equal(t, "rule-1", a.Limits[0].SourceID)
	assert.Equal(t, 100.0, a.Limits[0].Cap)
	assert.Equal(t, types.AllowanceSourcePolicy, a.Limits[1].Source)
	assert.False(t, a.Exhausted)

	spend(t, mgr, 100, 0)
	a = peerAllowance(t, mgr)
	assert.True(t, a.Exhausted, "the smaller account rule binds")
	assert.Equal(t, 100.0, a.Limits[0].Used)
	assert.Equal(t, 100.0, a.Limits[1].Used, "the policy window counted the same request")
}

func TestAllowance_RealStore_CatchAllIsUnlimited(t *testing.T) {
	// The uncapped policy wins selection, so the capped one never pays and
	// its cap is not listed.
	mgr, _ := allowanceFixture(t, []*types.Policy{
		allowPolicy("pol-open", []string{"grp-eng"}, types.PolicyLimits{}),
		allowPolicy("pol-capped", []string{"grp-eng"}, tokenLimits(10, 0, 3600)),
	})
	spend(t, mgr, 1000, 0)

	a := peerAllowance(t, mgr)
	assert.True(t, a.Unlimited)
	assert.False(t, a.Exhausted)
	assert.Empty(t, a.Limits, "no cap binds behind a catch-all policy")
}

func TestAllowance_RealStore_CatchAllWithAccountRuleIsNotUnlimited(t *testing.T) {
	mgr, _ := allowanceFixture(t,
		[]*types.Policy{allowPolicy("pol-open", []string{"grp-eng"}, types.PolicyLimits{})},
		allowRule("rule-usd", nil, []string{allowUser}, budgetLimits(20, 0, 2_592_000)),
	)

	a := peerAllowance(t, mgr)
	assert.False(t, a.Unlimited, "an account rule still binds")
	require.Len(t, a.Limits, 1)
	assert.Equal(t, types.AllowanceSourceAccountRule, a.Limits[0].Source)
	assert.Equal(t, types.AllowanceUnitUSD, a.Limits[0].Unit)
}

func TestAllowance_RealStore_ExhaustedPolicy(t *testing.T) {
	mgr, _ := allowanceFixture(t, []*types.Policy{allowPolicy("pol-user", []string{"grp-eng"}, tokenLimits(100, 0, 3600))})
	spend(t, mgr, 150, 0)

	a := peerAllowance(t, mgr)
	assert.True(t, a.Exhausted)
	require.Len(t, a.Limits, 1)
	assert.Equal(t, 150.0, a.Limits[0].Used, "used may overshoot the cap")
}

func TestAllowance_RealStore_SecondPolicyStillHasHeadroom(t *testing.T) {
	mgr, _ := allowanceFixture(t, []*types.Policy{
		allowPolicy("pol-big", []string{"grp-eng"}, tokenLimits(0, 1000, 3600)),
		allowPolicy("pol-small", []string{"grp-ops"}, tokenLimits(0, 100, 3600)),
	})
	spend(t, mgr, 1000, 0)

	a := peerAllowance(t, mgr)
	assert.False(t, a.Exhausted, "the smaller pool still pays")
	require.Len(t, a.Limits, 2)
	assert.Equal(t, "grp-eng", a.Limits[0].GroupID)
	assert.Equal(t, 1000.0, a.Limits[0].Used)
	assert.Equal(t, "grp-ops", a.Limits[1].GroupID)
	assert.Equal(t, 0.0, a.Limits[1].Used)
}

func TestAllowance_RealStore_PeerGroupsNotUserAutoGroups(t *testing.T) {
	// Everything here targets the user's auto-group, which the peer is not in.
	// The proxy never applies those caps to this peer, so neither may we.
	mgr, _ := allowanceFixture(t,
		[]*types.Policy{
			allowPolicy("pol-eng", []string{"grp-eng"}, tokenLimits(0, 500, 3600)),
			allowPolicy("pol-auto", []string{"grp-auto"}, tokenLimits(0, 1, 3600)),
		},
		allowRule("rule-auto", []string{"grp-auto"}, nil, tokenLimits(0, 1, 3600)),
	)

	a := peerAllowance(t, mgr)
	require.Len(t, a.Limits, 1, "only the peer-group policy applies")
	assert.Equal(t, "pol-eng", a.Limits[0].SourceID)
	assert.Equal(t, "grp-eng", a.Limits[0].GroupID)
	assert.False(t, a.Exhausted)
}

// TestAllowance_RealStore_ExhaustedMatchesSelector runs shared fixtures
// through both the peer answer and the proxy's selector after each spend, so
// Exhausted can never drift from what the proxy enforces.
func TestAllowance_RealStore_ExhaustedMatchesSelector(t *testing.T) {
	cases := []struct {
		name     string
		policies []*types.Policy
		rules    []*types.AccountBudgetRule
		spends   [][2]float64 // tokens, usd
	}{
		{
			name:     "policy user tokens",
			policies: []*types.Policy{allowPolicy("p", []string{"grp-eng"}, tokenLimits(100, 0, 3600))},
			spends:   [][2]float64{{50, 0}, {49, 0}, {1, 0}, {10, 0}},
		},
		{
			name:     "policy group budget",
			policies: []*types.Policy{allowPolicy("p", []string{"grp-ops"}, budgetLimits(0, 2, 86400))},
			spends:   [][2]float64{{0, 1}, {0, 0.99}, {0, 0.01}},
		},
		{
			name: "two pools",
			policies: []*types.Policy{
				allowPolicy("big", []string{"grp-eng"}, tokenLimits(0, 200, 3600)),
				allowPolicy("small", []string{"grp-ops"}, tokenLimits(0, 50, 3600)),
			},
			spends: [][2]float64{{150, 0}, {50, 0}, {49, 0}, {1, 0}},
		},
		{
			name:     "account rule over catch-all",
			policies: []*types.Policy{allowPolicy("open", []string{"grp-eng"}, types.PolicyLimits{})},
			rules:    []*types.AccountBudgetRule{allowRule("r", []string{"grp-ops"}, nil, tokenLimits(0, 80, 3600))},
			spends:   [][2]float64{{40, 0}, {39, 0}, {1, 0}},
		},
		{
			name:     "account usd rule under capped policy",
			policies: []*types.Policy{allowPolicy("p", []string{"grp-eng"}, tokenLimits(1000, 0, 3600))},
			rules:    []*types.AccountBudgetRule{allowRule("r", nil, []string{allowUser}, budgetLimits(1, 0, 86400))},
			spends:   [][2]float64{{10, 0.5}, {10, 0.5}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr, _ := allowanceFixture(t, tc.policies, tc.rules...)
			check := func(step int) {
				res, err := mgr.SelectPolicyForRequest(context.Background(), selectionInput())
				require.NoError(t, err)
				a := peerAllowance(t, mgr)
				assert.Equal(t, !res.Allow, a.Exhausted, "step %d: exhausted must equal the selector's deny", step)
			}
			check(0)
			for i, s := range tc.spends {
				spend(t, mgr, int64(s[0]), s[1])
				check(i + 1)
			}
		})
	}
}
