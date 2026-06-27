package agentnetwork

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	nbstatus "github.com/netbirdio/netbird/shared/management/status"
)

func newSelectorMgr(t *testing.T, ctrl *gomock.Controller) (*managerImpl, *store.MockStore) {
	t.Helper()
	mockStore := store.NewMockStore(ctrl)
	// SelectPolicyForRequest evaluates the account-budget ceiling before policy
	// selection. These policy-selection tests don't exercise account rules, so
	// default to "no rules" — the no-mock policyselect_realstore_test.go covers
	// the account gate's behavior end to end.
	mockStore.EXPECT().
		GetAccountAgentNetworkBudgetRules(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, nil).
		AnyTimes()
	return &managerImpl{store: mockStore}, mockStore
}

type usedKey struct {
	kind   types.ConsumptionDimension
	dimID  string
	window int64
}

// expectConsumptionBatch stubs the batched consumption read to return the
// supplied per-(kind, dim, window) counters, filling each row's window start
// from the actual request keys so it always matches what the selector computed.
// Keys absent from used resolve to zero counters.
func expectConsumptionBatch(mockStore *store.MockStore, used map[usedKey]*types.Consumption) {
	mockStore.EXPECT().
		GetAgentNetworkConsumptionBatch(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ store.LockingStrength, _ string, keys []types.ConsumptionKey) (map[types.ConsumptionKey]*types.Consumption, error) {
			out := make(map[types.ConsumptionKey]*types.Consumption)
			for _, k := range keys {
				if row, ok := used[usedKey{k.Kind, k.DimID, k.WindowSeconds}]; ok {
					rc := *row
					rc.WindowStartUTC = k.WindowStartUTC
					out[k] = &rc
				}
			}
			return out, nil
		}).
		AnyTimes()
}

func capPolicy(id, account string, sourceGroups []string, providerID string, tokenCap int64, windowSec int64) *types.Policy {
	return &types.Policy{
		ID:                     id,
		AccountID:              account,
		Enabled:                true,
		SourceGroups:           sourceGroups,
		DestinationProviderIDs: []string{providerID},
		Limits: types.PolicyLimits{
			TokenLimit: types.PolicyTokenLimit{
				Enabled:       true,
				GroupCap:      tokenCap,
				WindowSeconds: windowSec,
			},
		},
		CreatedAt: time.Now().UTC(),
	}
}

// TestSelectPolicy_NoApplicablePolicies covers the pass-through path:
// llm_router authorisation is upstream of selection; when the
// selector finds no policy targeting the (provider, caller-groups)
// combination, it returns Allow with no attribution and lets the
// request continue without consumption tracking.
func TestSelectPolicy_NoApplicablePolicies(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{}, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-x"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow, "no applicable policies = pass-through allow")
	assert.Empty(t, res.SelectedPolicyID, "no selection when nothing applies")
}

// TestSelectPolicy_AllowWithLowestGroupAttribution proves the v1
// attribution rule: when the caller's groups intersect a policy's
// source_groups in multiple positions, the selector picks the lowest
// group id by string sort so multi-node selection converges.
func TestSelectPolicy_AllowWithLowestGroupAttribution(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := capPolicy("pol-A", "acc-1", []string{"grp-zz", "grp-aa", "grp-mm"}, "prov-1", 10_000, 86_400)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policy}, nil)
	// Fresh: zero consumption across the board.
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-zz", "grp-aa", "grp-mm"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.True(t, res.Allow)
	assert.Equal(t, "pol-A", res.SelectedPolicyID)
	assert.Equal(t, "grp-aa", res.AttributionGroupID,
		"lowest-by-sort intersection wins so multi-node selection converges")
	assert.Equal(t, int64(86_400), res.WindowSeconds)
}

// TestSelectPolicy_LargerPoolWinsAcrossUsageLevels proves the core
// selection rule: among multiple applicable policies with caps, the
// selector picks the one with the larger absolute pool — at every
// usage level, not just at fresh state. The smaller-pool policy is
// only reached when the larger one is exhausted. This is the
// "drain biggest first" semantic operators expect for layered
// tiers; a fraction-based score would flap between the two as
// soon as one is partially used.
func TestSelectPolicy_LargerPoolWinsAcrossUsageLevels(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	tight := capPolicy("pol-tight", "acc-1", []string{"grp-engineers"}, "prov-1", 100, 86_400)
	tight.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wide := capPolicy("pol-wide", "acc-1", []string{"grp-engineers"}, "prov-1", 10_000, 86_400)
	wide.CreatedAt = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{tight, wide}, nil)

	// Both partially used. tight at 50/100 (50% used); wide at
	// 50/10000 (0.5% used). Old fraction-based algo would pick wide
	// here too — but for the wrong reason ("more relative slack").
	// New algo picks wide because its initial group cap is bigger
	// (10000 > 100), and that decision is stable as wide drains.
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {TokensInput: 50},
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-wide", res.SelectedPolicyID,
		"the policy with the bigger initial pool wins — operators expect 'drain the privileged tier first', not load-balance across tiers")
}

// TestSelectPolicy_StaysOnLargerPoolAfterPartialDrain locks the
// stickiness contract reported by operators: with two policies
// where A has a 200-token group cap and B has 150, the very first
// request goes to A AND every subsequent request continues to land
// on A until A's group cap is exhausted — at which point B becomes
// the only candidate. A fraction-based score would flap to B as
// soon as A had any consumption (B's 1.0 fraction beats A's 0.75)
// even though A still has more absolute headroom; that produced
// confusing per-policy attribution ledger entries and stranded
// A's remaining capacity behind B's exhaustion.
func TestSelectPolicy_StaysOnLargerPoolAfterPartialDrain(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policyA := capPolicy("pol-A-200", "acc-1", []string{"grp-engineers"}, "prov-1", 200, 86_400)
	policyB := capPolicy("pol-B-150", "acc-1", []string{"grp-engineers"}, "prov-1", 150, 86_400)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policyA, policyB}, nil)

	// A is partially drained (50/200 used = 25% used; 75% headroom
	// remaining). B is fresh (0/150). The old fraction-based score
	// would pick B here (1.0 > 0.75 fraction); the new pool-size
	// score sticks with A (200 > 150 absolute cap).
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {TokensInput: 50},
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-A-200", res.SelectedPolicyID,
		"once attribution lands on the bigger pool it must STAY there until exhausted — operators expect 'drain A then B', not 'flip to B as soon as A is touched'")
}

// TestSelectPolicy_FallsThroughToSmallerPoolWhenLargerExhausted
// proves the second half of the stickiness contract: once the
// larger-pool policy IS exhausted, the smaller one takes over.
// Without this we'd deny on requests the smaller policy is fully
// equipped to serve.
func TestSelectPolicy_FallsThroughToSmallerPoolWhenLargerExhausted(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policyA := capPolicy("pol-A-200", "acc-1", []string{"grp-engineers"}, "prov-1", 200, 86_400)
	// B uses a different window length so it has an INDEPENDENT counter — the
	// realistic shape for fall-through. On the SAME (group, window) tuple the
	// counter is shared, so A's cap of 200 being reached would also exhaust B's
	// 150; independent counters are what let A exhaust while B retains headroom.
	policyB := capPolicy("pol-B-150", "acc-1", []string{"grp-engineers"}, "prov-1", 150, 3_600)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policyA, policyB}, nil)

	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {TokensInput: 200}, // A: 200 >= 200 → exhausted
		{types.DimensionGroup, "grp-engineers", 3_600}:  {TokensInput: 100}, // B: 100 < 150 → headroom
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-B-150", res.SelectedPolicyID,
		"once the bigger pool is exhausted, the smaller one must take over — denying when capacity remains would strand B's allowance")
}

// TestSelectPolicy_TiebreakByLargerGroupPool covers the user-reported
// bug: an admin in two groups (Users + Admins) where Users is bound
// by a smaller-group-cap policy (50 group, 100 user) and Admins is
// bound by a bigger-group-cap policy (100 group, 20 user) MUST get
// attributed to the Admins policy on the first request.
//
// Without this rule, the fresh-state fraction is 1.0 for both and
// the older policy wins by created_at. The first 24-token request
// then drains the shared user counter past Admins's tight 20-token
// user cap, locking Admins out of selection forever. The 100-token
// Admins group pool ends up stranded while requests pile onto the
// 50-token Users pool — the opposite of what the operator intended
// when they put the bigger pool on the privileged group.
func TestSelectPolicy_TiebreakByLargerGroupPool(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	// Policy A: Users group, smaller group pool, looser per-user cap.
	policyA := &types.Policy{
		ID:                     "pol-Users",
		AccountID:              "acc-1",
		Enabled:                true,
		SourceGroups:           []string{"grp-Users"},
		DestinationProviderIDs: []string{"prov-1"},
		Limits: types.PolicyLimits{
			TokenLimit: types.PolicyTokenLimit{
				Enabled: true, GroupCap: 50, UserCap: 100, WindowSeconds: 86_400,
			},
		},
		// Older — would win the legacy created_at tiebreak.
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	// Policy B: Admins group, bigger group pool, tighter per-user cap.
	policyB := &types.Policy{
		ID:                     "pol-Admins",
		AccountID:              "acc-1",
		Enabled:                true,
		SourceGroups:           []string{"grp-Admins"},
		DestinationProviderIDs: []string{"prov-1"},
		Limits: types.PolicyLimits{
			TokenLimit: types.PolicyTokenLimit{
				Enabled: true, GroupCap: 100, UserCap: 20, WindowSeconds: 86_400,
			},
		},
		CreatedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policyA, policyB}, nil)
	// Fresh state: every cap evaluation reads zero usage.
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		UserID:     "user-1",
		GroupIDs:   []string{"grp-Users", "grp-Admins"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-Admins", res.SelectedPolicyID,
		"the bigger group pool wins the fresh-state tiebreak — picking Users first would burn the shared user counter past Admins's tight user cap on the very first request and strand the bigger Admins pool")
	assert.Equal(t, "grp-Admins", res.AttributionGroupID)
}

// TestSelectPolicy_TiebreakByCreatedAt proves the deterministic
// final tiebreak: when two applicable policies have the same
// headroom fraction AND the same group cap (so the larger-pool rule
// can't differentiate either), the older policy wins so attribution
// is stable across replays.
func TestSelectPolicy_TiebreakByCreatedAt(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	older := capPolicy("pol-old", "acc-1", []string{"grp-engineers"}, "prov-1", 1_000, 86_400)
	older.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := capPolicy("pol-new", "acc-1", []string{"grp-engineers"}, "prov-1", 1_000, 86_400)
	newer.CreatedAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{newer, older}, nil)
	// Both at zero consumption → identical headroom fraction.
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-old", res.SelectedPolicyID,
		"older policy wins on equal-headroom tiebreak so attribution is stable across replays")
}

// TestSelectPolicy_DeniesWhenAllExhausted proves the deny envelope:
// when every applicable policy has at least one cap fully exhausted,
// the selector returns Allow=false with the most-recent exhaustion's
// deny code + human reason. The proxy's middleware surfaces this as
// a 403 with the canonical llm_policy.* code.
func TestSelectPolicy_DeniesWhenAllExhausted(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	a := capPolicy("pol-a", "acc-1", []string{"grp-engineers"}, "prov-1", 100, 86_400)
	b := capPolicy("pol-b", "acc-1", []string{"grp-engineers"}, "prov-1", 200, 86_400)
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{a, b}, nil)

	// Shared group counter at 200: A (cap 100) and B (cap 200) both exhausted.
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {TokensInput: 200},
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.False(t, res.Allow, "every applicable policy exhausted = deny")
	assert.Equal(t, denyCodeTokenCapExceeded, res.DenyCode)
	assert.Contains(t, res.DenyReason, "token cap exhausted",
		"deny reason must name the exhausted cap kind for operator debugging")
}

// TestSelectPolicy_UncappedPolicyAlwaysWinsAgainstCapped proves the
// catch-all-allow contract: a policy with NO enabled caps wins
// against any capped policy regardless of how much headroom the
// capped one has, because operators who configure unlimited access
// expect requests to attribute there until they explicitly add caps.
func TestSelectPolicy_UncappedPolicyAlwaysWinsAgainstCapped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	uncapped := &types.Policy{
		ID:                     "pol-uncapped",
		AccountID:              "acc-1",
		Enabled:                true,
		SourceGroups:           []string{"grp-engineers"},
		DestinationProviderIDs: []string{"prov-1"},
		// All Limits.*.Enabled = false (zero-value).
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	wide := capPolicy("pol-wide", "acc-1", []string{"grp-engineers"}, "prov-1", 1_000_000, 86_400)
	wide.CreatedAt = time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC) // older than uncapped

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{uncapped, wide}, nil)
	// Only the wide policy reads consumption; uncapped doesn't query
	// because it has no enabled caps.
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-uncapped", res.SelectedPolicyID,
		"a no-caps policy must always win selection — that's how operators express 'unlimited access through this path'")
	assert.Equal(t, int64(0), res.WindowSeconds, "no caps configured = WindowSeconds=0 so RecordLLMUsage skips counter writes")
}

// TestSelectPolicy_DisabledPolicyIgnored proves disabled policies
// don't count toward selection — even when they'd otherwise be the
// best match. Operators disable a policy to take it offline; the
// selector must respect that and route through whatever's left.
func TestSelectPolicy_DisabledPolicyIgnored(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	disabled := capPolicy("pol-disabled", "acc-1", []string{"grp-engineers"}, "prov-1", 1_000_000, 86_400)
	disabled.Enabled = false
	enabled := capPolicy("pol-enabled", "acc-1", []string{"grp-engineers"}, "prov-1", 100, 86_400)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{disabled, enabled}, nil)
	expectConsumptionBatch(mockStore, nil)

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "pol-enabled", res.SelectedPolicyID,
		"disabled policies must be ignored at selection time")
}

// TestSelectPolicy_StoreErrorPropagates locks the no-fail-open
// contract: a transient store error must surface to the caller, not
// be silently treated as "no policies = allow". A false allow on the
// hot path would let a request slip past every cap.
func TestSelectPolicy_StoreErrorPropagates(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return(nil, errors.New("boom"))

	_, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID: "acc-1",
	})
	require.Error(t, err, "store errors must surface — never fail open on the hot path")
}

// TestSelectPolicy_RejectsEmptyAccount is the input-validation guard:
// empty account_id is a programmer error and must surface as
// InvalidArgument, not as a silent zero-result lookup.
func TestSelectPolicy_RejectsEmptyAccount(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, _ := newSelectorMgr(t, ctrl)

	_, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{})
	require.Error(t, err)
	var sErr *nbstatus.Error
	require.True(t, errors.As(err, &sErr))
	assert.Equal(t, nbstatus.InvalidArgument, sErr.Type())
}

// TestSelectPolicy_SharesGroupCounterAcrossPolicies locks the
// counter-keying design fork: counters are keyed on (account,
// dim_kind, dim_id, window_hours, window_start) — NOT on policy_id.
// Two policies that target the same group with the SAME window length
// share one bucket: spend booked under policy A is visible to policy
// B's headroom calculation and counts toward B's cap.
//
// This is what makes "operator's per-group enforcement" sane — caps
// describe how much a GROUP can use, not how much each policy owes.
func TestSelectPolicy_SharesGroupCounterAcrossPolicies(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	// Two policies, both targeting grp-engineers + prov-1, same 24h
	// window length. Different cap sizes.
	policyA := capPolicy("pol-A", "acc-1", []string{"grp-engineers"}, "prov-1", 1_000, 86_400)
	policyB := capPolicy("pol-B", "acc-1", []string{"grp-engineers"}, "prov-1", 5_000, 86_400)

	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policyA, policyB}, nil)
	// Both policies query the SAME consumption row — same dim_id,
	// same window_hours, same window_start. The mock returns the
	// same row for both calls, simulating the shared counter.
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {TokensInput: 800},
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	// 800 used → policy A has 200 tokens left of 1000 (20% headroom);
	// policy B has 4200 left of 5000 (84% headroom). B wins.
	assert.Equal(t, "pol-B", res.SelectedPolicyID,
		"the SAME 800 tokens count toward both policies — counters share the (group, window) key, caps differ per policy")
}

// TestSelectPolicy_AntiFallThroughOnLowestGroup locks the no-fall-
// through behaviour: when a caller is in multiple of a policy's
// source_groups and the lowest-by-sort group is exhausted, we DENY
// rather than fall through to a less-loaded sibling. Per-group caps
// are independent (each group has its own bucket), but attribution
// is one-shot — operators wanting fall-through must split into
// separate policies.
//
// This nails down semantics future contributors might "improve" into
// fall-through behaviour by accident.
func TestSelectPolicy_AntiFallThroughOnLowestGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	// Policy targets two groups; caller is in both.
	policy := capPolicy("pol-1", "acc-1", []string{"grp-aaa", "grp-bbb"}, "prov-1", 100, 86_400)
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policy}, nil)

	// grp-aaa is the lowest by sort → attribution picks it, and the
	// prefetch only collects the attribution group's key. We exhaust
	// grp-aaa (100/100); grp-bbb's counter is never requested because the
	// selector attributes one-shot to the lowest group, so it can't fall
	// through to a less-loaded sibling.
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-aaa", 86_400}: {TokensInput: 100},
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-aaa", "grp-bbb"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.False(t, res.Allow,
		"lowest-group-by-sort attribution does NOT fall through to a less-loaded sibling — operators wanting fall-through must split into separate policies")
	assert.Equal(t, denyCodeTokenCapExceeded, res.DenyCode)
	assert.Contains(t, res.DenyReason, "pol-1",
		"deny reason names the exhausted policy id so operators can grep it from the access log")
}

// TestSelectPolicy_BudgetOnlyExhaustionDenies covers the symmetric
// path to TestSelectPolicy_DeniesWhenAllExhausted but for the budget
// cap: a policy with token_limit DISABLED and budget_limit at-cap
// must deny with llm_policy.budget_cap_exceeded (not the token code).
//
// Without this, the budget evaluation path in evalBudgetCap could
// silently regress and we'd still pass DeniesWhenAllExhausted (which
// only exercises tokens).
func TestSelectPolicy_BudgetOnlyExhaustionDenies(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := &types.Policy{
		ID:                     "pol-budget",
		AccountID:              "acc-1",
		Enabled:                true,
		SourceGroups:           []string{"grp-engineers"},
		DestinationProviderIDs: []string{"prov-1"},
		Limits: types.PolicyLimits{
			TokenLimit: types.PolicyTokenLimit{Enabled: false},
			BudgetLimit: types.PolicyBudgetLimit{
				Enabled:       true,
				GroupCapUsd:   10.00,
				WindowSeconds: 86_400,
			},
		},
		CreatedAt: time.Now().UTC(),
	}
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policy}, nil)
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {CostUSD: 10.50}, // over the $10 cap
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.False(t, res.Allow, "budget cap exhausted must deny independently of any token cap state")
	assert.Equal(t, denyCodeBudgetCapExceeded, res.DenyCode,
		"deny code must be the budget code — token-only deny would silently regress the budget evaluation path")
	assert.Contains(t, res.DenyReason, "budget", "deny reason names the budget cap kind for operator debugging")
}

// TestSelectPolicy_BudgetTighterThanTokenWins is the dual-cap headroom
// fork: when both Token and Budget are enabled on the same policy,
// the SMALLER remaining ratio gates the policy. A policy with
// abundant token headroom but near-zero budget headroom must deny on
// budget, not pass on tokens.
func TestSelectPolicy_BudgetTighterThanTokenWins(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr, mockStore := newSelectorMgr(t, ctrl)

	policy := &types.Policy{
		ID:                     "pol-dual",
		AccountID:              "acc-1",
		Enabled:                true,
		SourceGroups:           []string{"grp-engineers"},
		DestinationProviderIDs: []string{"prov-1"},
		Limits: types.PolicyLimits{
			TokenLimit:  types.PolicyTokenLimit{Enabled: true, GroupCap: 10_000_000, WindowSeconds: 86_400},
			BudgetLimit: types.PolicyBudgetLimit{Enabled: true, GroupCapUsd: 1.00, WindowSeconds: 86_400},
		},
		CreatedAt: time.Now().UTC(),
	}
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(gomock.Any(), gomock.Any(), "acc-1").
		Return([]*types.Policy{policy}, nil)
	// One shared counter carries both token usage (ample headroom) and cost
	// (at the $1 budget cap); the tighter budget cap gates the policy.
	expectConsumptionBatch(mockStore, map[usedKey]*types.Consumption{
		{types.DimensionGroup, "grp-engineers", 86_400}: {TokensInput: 100, CostUSD: 1.00},
	})

	res, err := mgr.SelectPolicyForRequest(context.Background(), PolicySelectionInput{
		AccountID:  "acc-1",
		GroupIDs:   []string{"grp-engineers"},
		ProviderID: "prov-1",
	})
	require.NoError(t, err)
	assert.False(t, res.Allow,
		"the tighter of (token, budget) wins — abundant token headroom must NOT mask an exhausted budget")
	assert.Equal(t, denyCodeBudgetCapExceeded, res.DenyCode)
}
