package agentnetwork

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/netbirdio/netbird/management/server/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// validateUsageDeltas rejects negative or non-finite usage counters before they
// reach the consumption store, so a bad delta can't decrement or poison totals.
// The store batch method enforces the same invariant; this is the manager-level
// guard so direct callers fail fast with a clear error.
func validateUsageDeltas(tokensIn, tokensOut int64, costUSD float64) error {
	if tokensIn < 0 || tokensOut < 0 || costUSD < 0 || math.IsNaN(costUSD) || math.IsInf(costUSD, 0) {
		return status.Errorf(status.InvalidArgument, "usage deltas must be non-negative and finite")
	}
	return nil
}

// Deny codes the proxy surfaces back to the caller when every
// applicable policy is exhausted. The proxy converts these into
// upstream-shaped error responses.
const (
	//nolint:gosec // policy deny code label, not a credential
	denyCodeTokenCapExceeded = "llm_policy.token_cap_exceeded"
	//nolint:gosec // policy deny code label, not a credential
	denyCodeBudgetCapExceeded = "llm_policy.budget_cap_exceeded"
	//nolint:gosec // account deny code label, not a credential
	denyCodeAccountTokenCapExceeded = "llm_account.token_cap_exceeded"
	//nolint:gosec // account deny code label, not a credential
	denyCodeAccountBudgetCapExceeded = "llm_account.budget_cap_exceeded"
)

// consumptionCache holds the consumption counters prefetched for one
// policy-selection request, keyed by ConsumptionKey. A miss returns a zero
// counter — the same contract the store's single-row getter uses for absent
// rows — so the eval logic is identical whether a counter exists yet or not.
type consumptionCache map[types.ConsumptionKey]*types.Consumption

func (c consumptionCache) get(accountID string, kind types.ConsumptionDimension, dimID string, windowSeconds int64, windowStart time.Time) *types.Consumption {
	key := types.ConsumptionKey{Kind: kind, DimID: dimID, WindowSeconds: windowSeconds, WindowStartUTC: windowStart.UTC()}
	if row, ok := c[key]; ok && row != nil {
		return row
	}
	return &types.Consumption{
		AccountID:      accountID,
		DimensionKind:  kind,
		DimensionID:    dimID,
		WindowSeconds:  windowSeconds,
		WindowStartUTC: windowStart.UTC(),
	}
}

// addLimitKeys records the user/group consumption keys a single enabled (token
// or budget) limit window reads for the given attribution group, into a dedup
// set. attrGroup may be empty (no group dimension applies).
func addLimitKeys(set map[types.ConsumptionKey]struct{}, userID, attrGroup string, windowSeconds int64, now time.Time) {
	if windowSeconds <= 0 {
		return
	}
	ws := types.WindowStart(now, windowSeconds)
	if userID != "" {
		set[types.ConsumptionKey{Kind: types.DimensionUser, DimID: userID, WindowSeconds: windowSeconds, WindowStartUTC: ws}] = struct{}{}
	}
	if attrGroup != "" {
		set[types.ConsumptionKey{Kind: types.DimensionGroup, DimID: attrGroup, WindowSeconds: windowSeconds, WindowStartUTC: ws}] = struct{}{}
	}
}

// prefetchConsumption loads, in one store round-trip, every consumption counter
// that the account-budget ceiling and the candidate policies will read while
// scoring this request. This replaces the per-cap point reads the selector
// previously issued one at a time (the N+1 on the hot path).
func (m *managerImpl) prefetchConsumption(ctx context.Context, in PolicySelectionInput, rules []*types.AccountBudgetRule, candidates []*types.Policy, now time.Time) (consumptionCache, error) {
	set := make(map[types.ConsumptionKey]struct{})
	for _, p := range candidates {
		attr := lowestIntersect(p.SourceGroups, in.GroupIDs)
		if p.Limits.TokenLimit.Enabled {
			addLimitKeys(set, in.UserID, attr, p.Limits.TokenLimit.WindowSeconds, now)
		}
		if p.Limits.BudgetLimit.Enabled {
			addLimitKeys(set, in.UserID, attr, p.Limits.BudgetLimit.WindowSeconds, now)
		}
	}
	for _, r := range rules {
		if r == nil || !r.Enabled || !budgetRuleApplies(r, in) {
			continue
		}
		attr := lowestIntersect(r.TargetGroups, in.GroupIDs)
		if r.Limits.TokenLimit.Enabled {
			addLimitKeys(set, in.UserID, attr, r.Limits.TokenLimit.WindowSeconds, now)
		}
		if r.Limits.BudgetLimit.Enabled {
			addLimitKeys(set, in.UserID, attr, r.Limits.BudgetLimit.WindowSeconds, now)
		}
	}
	if len(set) == 0 {
		return consumptionCache{}, nil
	}
	keys := make([]types.ConsumptionKey, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	rows, err := m.store.GetAgentNetworkConsumptionBatch(ctx, store.LockingStrengthNone, in.AccountID, keys)
	if err != nil {
		return nil, fmt.Errorf("batch read consumption: %w", err)
	}
	return consumptionCache(rows), nil
}

// SelectPolicyForRequest picks the policy that "pays" for the
// incoming request. The chosen policy is the one with the largest
// pool that still has headroom — drain the bigger bucket first,
// fall through to the next-biggest only when the current one's
// group cap or shared per-user cap is exhausted. This matches
// operator intuition for layered tiers ("privileged group has the
// 10k budget, regular group has 1k as the safety net") and avoids
// the load-balancer flapping that fraction-based scoring produces
// once any cap has been touched.
//
// Ordering across non-exhausted candidates:
//  1. Policies with NO enabled caps (catch-all-allow) win over any
//     capped policy — operators who configure unlimited access
//     expect requests to attribute there until they explicitly add
//     caps.
//  2. Larger group token cap wins.
//  3. Larger group budget USD cap wins.
//  4. Larger user token cap wins.
//  5. Larger user budget USD cap wins.
//  6. Older created_at wins (deterministic final tiebreak so
//     multi-node selection converges).
//
// Returns Allow=true with empty SelectedPolicyID when no policy in
// the account targets the (provider, caller-groups) combination —
// llm_router is the gate that owns "no policy authorises this
// request" semantics; this function trusts that authorisation has
// already happened upstream and only does the limit-aware
// attribution.
func (m *managerImpl) SelectPolicyForRequest(ctx context.Context, in PolicySelectionInput) (*PolicySelectionResult, error) {
	if in.AccountID == "" {
		return nil, status.Errorf(status.InvalidArgument, "account_id is required")
	}

	now := time.Now().UTC()

	rules, err := m.store.GetAccountAgentNetworkBudgetRules(ctx, store.LockingStrengthNone, in.AccountID)
	if err != nil {
		return nil, fmt.Errorf("list account budget rules: %w", err)
	}
	policies, err := m.store.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, in.AccountID)
	if err != nil {
		return nil, fmt.Errorf("list account policies: %w", err)
	}
	candidates := filterApplicablePolicies(policies, in)

	// Prefetch every consumption counter the ceiling + candidate policies will
	// read, in a single store round-trip, then score against the cache.
	cache, err := m.prefetchConsumption(ctx, in, rules, candidates, now)
	if err != nil {
		return nil, err
	}

	// Account-level budget rules are an always-on ceiling, evaluated
	// independently of policy selection (they bind even for catch-all-allow
	// policies or requests that match no policy). All applicable rules must
	// pass — this is where min-wins lives.
	if deny, code, reason := checkAccountBudget(in, rules, cache, now); deny {
		return &PolicySelectionResult{Allow: false, DenyCode: code, DenyReason: reason}, nil
	}

	if len(candidates) == 0 {
		return &PolicySelectionResult{Allow: true}, nil
	}
	scored, lastDenyCode, lastDenyReason := scoreCandidates(in, candidates, cache, now)
	if len(scored) == 0 {
		return &PolicySelectionResult{
			Allow:      false,
			DenyCode:   lastDenyCode,
			DenyReason: lastDenyReason,
		}, nil
	}

	sort.SliceStable(scored, func(i, j int) bool {
		// Catch-all-allow (no caps configured) wins outright over
		// any capped policy.
		iNoCap := isUncapped(scored[i].policy)
		jNoCap := isUncapped(scored[j].policy)
		if iNoCap != jNoCap {
			return iNoCap
		}
		// Bigger pool drains first. Group caps dominate (shared
		// across the group) before individual caps.
		if a, b := groupCapTokens(scored[i].policy), groupCapTokens(scored[j].policy); a != b {
			return a > b
		}
		if a, b := groupCapBudgetUsd(scored[i].policy), groupCapBudgetUsd(scored[j].policy); a != b {
			return a > b
		}
		if a, b := userCapTokens(scored[i].policy), userCapTokens(scored[j].policy); a != b {
			return a > b
		}
		if a, b := userCapBudgetUsd(scored[i].policy), userCapBudgetUsd(scored[j].policy); a != b {
			return a > b
		}
		return scored[i].policy.CreatedAt.Before(scored[j].policy.CreatedAt)
	})

	winner := scored[0]
	return &PolicySelectionResult{
		Allow:              true,
		SelectedPolicyID:   winner.policy.ID,
		AttributionGroupID: winner.attributionGroup,
		WindowSeconds:      winner.windowSeconds,
	}, nil
}

// filterApplicablePolicies returns the enabled policies that target
// the requested provider and have at least one of the caller's groups
// in their source_groups. Caller's group set is matched
// case-sensitively against policy.SourceGroups.
func filterApplicablePolicies(policies []*types.Policy, in PolicySelectionInput) []*types.Policy {
	if len(policies) == 0 {
		return nil
	}
	groupSet := make(map[string]struct{}, len(in.GroupIDs))
	for _, g := range in.GroupIDs {
		if g != "" {
			groupSet[g] = struct{}{}
		}
	}
	out := make([]*types.Policy, 0, len(policies))
	for _, p := range policies {
		if p == nil || !p.Enabled {
			continue
		}
		if !sliceContains(p.DestinationProviderIDs, in.ProviderID) {
			continue
		}
		if !anyGroupMatches(p.SourceGroups, groupSet) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// candidate is the per-policy intermediate the selector ranks. A
// policy that's been exhausted on any enabled cap never makes it
// into this slice; the selector's deny envelope carries the latest
// exhaustion's reason out separately.
type candidate struct {
	policy           *types.Policy
	attributionGroup string
	windowSeconds    int64
}

// scoreCandidates evaluates every applicable policy against the
// caller's current consumption. Exhausted policies are filtered out
// of the returned slice; the most recent exhaustion's deny code +
// human reason is returned alongside so the caller can surface it
// when no candidate survives.
func scoreCandidates(
	in PolicySelectionInput,
	candidates []*types.Policy,
	cache consumptionCache,
	now time.Time,
) ([]candidate, string, string) {
	out := make([]candidate, 0, len(candidates))
	var lastDenyCode, lastDenyReason string

	for _, p := range candidates {
		c, exhausted, denyCode, denyReason := scoreOne(in, p, cache, now)
		if exhausted {
			lastDenyCode = denyCode
			lastDenyReason = denyReason
			continue
		}
		out = append(out, c)
	}
	return out, lastDenyCode, lastDenyReason
}

// scoreOne checks a single policy for cap exhaustion. Returns the
// candidate envelope when the policy still has headroom on every
// enabled cap; reports exhausted=true with a deny code naming the
// offending cap kind otherwise.
func scoreOne(
	in PolicySelectionInput,
	p *types.Policy,
	cache consumptionCache,
	now time.Time,
) (candidate, bool, string, string) {
	attrGroup := lowestIntersect(p.SourceGroups, in.GroupIDs)
	c := candidate{
		policy:           p,
		attributionGroup: attrGroup,
		windowSeconds:    effectiveWindowSeconds(p),
	}

	if p.Limits.TokenLimit.Enabled && p.Limits.TokenLimit.WindowSeconds > 0 {
		if exhausted, reason := evalTokenCap(cache, in.AccountID, in.UserID, attrGroup, p.Limits.TokenLimit, now, "policy "+p.ID); exhausted {
			return candidate{}, true, denyCodeTokenCapExceeded, reason
		}
	}

	if p.Limits.BudgetLimit.Enabled && p.Limits.BudgetLimit.WindowSeconds > 0 {
		if exhausted, reason := evalBudgetCap(cache, in.AccountID, in.UserID, attrGroup, p.Limits.BudgetLimit, now, "policy "+p.ID); exhausted {
			return candidate{}, true, denyCodeBudgetCapExceeded, reason
		}
	}

	return c, false, "", ""
}

// evalTokenCap reports whether the token limit is already exhausted for the
// caller in its own window. attrGroup may be empty (no group dimension applies).
// label identifies the cap source ("policy <id>" or "account rule <id>") for the
// deny reason. It is the shared primitive behind both policy and account-rule
// enforcement.
func evalTokenCap(
	cache consumptionCache,
	accountID, userID, attrGroup string,
	tl types.PolicyTokenLimit,
	now time.Time,
	label string,
) (bool, string) {
	windowStart := types.WindowStart(now, tl.WindowSeconds)

	if tl.UserCap > 0 && userID != "" {
		row := cache.get(accountID, types.DimensionUser, userID, tl.WindowSeconds, windowStart)
		used := row.TokensInput + row.TokensOutput
		if used >= tl.UserCap {
			return true, fmt.Sprintf("user token cap exhausted on %s (used %d of %d)", label, used, tl.UserCap)
		}
	}

	if tl.GroupCap > 0 && attrGroup != "" {
		row := cache.get(accountID, types.DimensionGroup, attrGroup, tl.WindowSeconds, windowStart)
		used := row.TokensInput + row.TokensOutput
		if used >= tl.GroupCap {
			return true, fmt.Sprintf("group token cap exhausted on %s (used %d of %d)", label, used, tl.GroupCap)
		}
	}

	return false, ""
}

// evalBudgetCap is the budget (USD) counterpart of evalTokenCap.
func evalBudgetCap(
	cache consumptionCache,
	accountID, userID, attrGroup string,
	bl types.PolicyBudgetLimit,
	now time.Time,
	label string,
) (bool, string) {
	windowStart := types.WindowStart(now, bl.WindowSeconds)

	if bl.UserCapUsd > 0 && userID != "" {
		row := cache.get(accountID, types.DimensionUser, userID, bl.WindowSeconds, windowStart)
		if row.CostUSD >= bl.UserCapUsd {
			return true, fmt.Sprintf("user budget cap exhausted on %s (used $%.4f of $%.4f)", label, row.CostUSD, bl.UserCapUsd)
		}
	}

	if bl.GroupCapUsd > 0 && attrGroup != "" {
		row := cache.get(accountID, types.DimensionGroup, attrGroup, bl.WindowSeconds, windowStart)
		if row.CostUSD >= bl.GroupCapUsd {
			return true, fmt.Sprintf("group budget cap exhausted on %s (used $%.4f of $%.4f)", label, row.CostUSD, bl.GroupCapUsd)
		}
	}

	return false, ""
}

// checkAccountBudget evaluates every applicable account-level budget rule as an
// all-must-pass ceiling. A rule applies when the caller is in its TargetUsers,
// one of its TargetGroups, or it has no targets at all (account-wide). Returns
// deny=true with an llm_account.* code on the first exhausted rule. Group caps
// attribute to the lowest intersecting group (the same model policies use), so
// multi-group behavior is unchanged.
func checkAccountBudget(in PolicySelectionInput, rules []*types.AccountBudgetRule, cache consumptionCache, now time.Time) (bool, string, string) {
	for _, r := range rules {
		if r == nil || !r.Enabled || !budgetRuleApplies(r, in) {
			continue
		}
		attrGroup := lowestIntersect(r.TargetGroups, in.GroupIDs)
		label := "account rule " + r.ID

		if r.Limits.TokenLimit.Enabled && r.Limits.TokenLimit.WindowSeconds > 0 {
			if exhausted, reason := evalTokenCap(cache, in.AccountID, in.UserID, attrGroup, r.Limits.TokenLimit, now, label); exhausted {
				return true, denyCodeAccountTokenCapExceeded, reason
			}
		}

		if r.Limits.BudgetLimit.Enabled && r.Limits.BudgetLimit.WindowSeconds > 0 {
			if exhausted, reason := evalBudgetCap(cache, in.AccountID, in.UserID, attrGroup, r.Limits.BudgetLimit, now, label); exhausted {
				return true, denyCodeAccountBudgetCapExceeded, reason
			}
		}
	}

	return false, "", ""
}

// budgetRuleApplies reports whether an account budget rule binds the caller:
// a direct user match, a group intersection, or an untargeted (account-wide)
// rule.
func budgetRuleApplies(r *types.AccountBudgetRule, in PolicySelectionInput) bool {
	if len(r.TargetUsers) == 0 && len(r.TargetGroups) == 0 {
		return true
	}
	if in.UserID != "" && sliceContains(r.TargetUsers, in.UserID) {
		return true
	}
	groupSet := make(map[string]struct{}, len(in.GroupIDs))
	for _, g := range in.GroupIDs {
		if g != "" {
			groupSet[g] = struct{}{}
		}
	}
	return anyGroupMatches(r.TargetGroups, groupSet)
}

// RecordAccountBudgetUsage fans the served request's usage out to every
// applicable account budget rule's own (dimension, window) counter. The user
// dimension is always booked when a rule has a user-applicable cap; the group
// dimension books against the rule's lowest intersecting group. This runs
// alongside the policy-window record so account ceilings accumulate in their own
// windows (commonly monthly) independently of the per-policy window.
func (m *managerImpl) RecordAccountBudgetUsage(ctx context.Context, accountID, userID string, groupIDs []string, tokensIn, tokensOut int64, costUSD float64) error {
	if accountID == "" {
		return status.Errorf(status.InvalidArgument, "account_id is required")
	}
	if err := validateUsageDeltas(tokensIn, tokensOut, costUSD); err != nil {
		return err
	}
	rules, err := m.store.GetAccountAgentNetworkBudgetRules(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("list account budget rules: %w", err)
	}
	set := make(map[types.ConsumptionKey]struct{})
	addAccountBudgetKeys(set, PolicySelectionInput{AccountID: accountID, UserID: userID, GroupIDs: groupIDs}, rules, time.Now().UTC())
	if len(set) == 0 {
		return nil
	}
	return m.store.IncrementAgentNetworkConsumptionBatch(ctx, accountID, keysSlice(set), tokensIn, tokensOut, costUSD)
}

// RecordUsageInput carries everything RecordUsage books for one served request.
type RecordUsageInput struct {
	AccountID          string
	UserID             string
	AttributionGroupID string // selected policy's attribution group (policy window)
	GroupIDs           []string
	WindowSeconds      int64 // selected policy's window; 0 means no policy cap
	TokensIn           int64
	TokensOut          int64
	CostUSD            float64
}

// RecordUsage books a served request's usage against every counter it touches —
// the selected policy's per-(user, group) window plus every applicable account
// budget rule's own window — deduplicated and written in a single transaction.
// Two counters that collapse to the same (dimension, window) tuple are booked
// once, so a single request can never double-count against one cap.
func (m *managerImpl) RecordUsage(ctx context.Context, in RecordUsageInput) error {
	if in.AccountID == "" {
		return status.Errorf(status.InvalidArgument, "account_id is required")
	}
	if err := validateUsageDeltas(in.TokensIn, in.TokensOut, in.CostUSD); err != nil {
		return err
	}
	now := time.Now().UTC()
	set := make(map[types.ConsumptionKey]struct{})

	// Policy-window dimensions are booked only when a policy cap bound this
	// request (window > 0). A zero window means catch-all-allow / no policy cap;
	// the account fan-out below still books against the budget rules' windows.
	if in.WindowSeconds > 0 {
		addLimitKeys(set, in.UserID, in.AttributionGroupID, in.WindowSeconds, now)
	}

	rules, err := m.store.GetAccountAgentNetworkBudgetRules(ctx, store.LockingStrengthNone, in.AccountID)
	if err != nil {
		return fmt.Errorf("list account budget rules: %w", err)
	}
	addAccountBudgetKeys(set, PolicySelectionInput{AccountID: in.AccountID, UserID: in.UserID, GroupIDs: in.GroupIDs}, rules, now)

	if len(set) == 0 {
		return nil
	}
	return m.store.IncrementAgentNetworkConsumptionBatch(ctx, in.AccountID, keysSlice(set), in.TokensIn, in.TokensOut, in.CostUSD)
}

// addAccountBudgetKeys adds the (dimension, window) keys a served request books
// against every applicable account budget rule into the dedup set.
func addAccountBudgetKeys(set map[types.ConsumptionKey]struct{}, in PolicySelectionInput, rules []*types.AccountBudgetRule, now time.Time) {
	for _, r := range rules {
		if r == nil || !r.Enabled || !budgetRuleApplies(r, in) {
			continue
		}
		attrGroup := lowestIntersect(r.TargetGroups, in.GroupIDs)
		for _, window := range ruleWindows(r) {
			addLimitKeys(set, in.UserID, attrGroup, window, now)
		}
	}
}

// keysSlice flattens a ConsumptionKey set into a slice.
func keysSlice(set map[types.ConsumptionKey]struct{}) []types.ConsumptionKey {
	keys := make([]types.ConsumptionKey, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	return keys
}

// ruleWindows returns the distinct enabled window lengths a budget rule books
// against (token window and/or budget window, deduplicated).
func ruleWindows(r *types.AccountBudgetRule) []int64 {
	var windows []int64
	if r.Limits.TokenLimit.Enabled && r.Limits.TokenLimit.WindowSeconds > 0 {
		windows = append(windows, r.Limits.TokenLimit.WindowSeconds)
	}
	if r.Limits.BudgetLimit.Enabled && r.Limits.BudgetLimit.WindowSeconds > 0 {
		bw := r.Limits.BudgetLimit.WindowSeconds
		if len(windows) == 0 || windows[0] != bw {
			windows = append(windows, bw)
		}
	}
	return windows
}

// effectiveWindowSeconds returns the window length the proxy should
// hand back to RecordLLMUsage. When both halves are enabled with
// different windows, token_limit wins (the more common config); when
// only one is enabled that one wins; when neither is enabled the
// returned value is 0 — RecordLLMUsage treats 0 as "no limit
// tracking" and skips the increment, which is the right pass-through
// for catch-all-allow policies with no caps configured.
func effectiveWindowSeconds(p *types.Policy) int64 {
	if p.Limits.TokenLimit.Enabled && p.Limits.TokenLimit.WindowSeconds > 0 {
		return p.Limits.TokenLimit.WindowSeconds
	}
	if p.Limits.BudgetLimit.Enabled && p.Limits.BudgetLimit.WindowSeconds > 0 {
		return p.Limits.BudgetLimit.WindowSeconds
	}
	return 0
}

// lowestIntersect returns the lowest-by-string-sort element of
// callerGroups ∩ sourceGroups. Empty when the intersection is empty.
// Lowest is deterministic so multi-node selection converges.
func lowestIntersect(sourceGroups, callerGroups []string) string {
	if len(sourceGroups) == 0 || len(callerGroups) == 0 {
		return ""
	}
	srcSet := make(map[string]struct{}, len(sourceGroups))
	for _, g := range sourceGroups {
		srcSet[g] = struct{}{}
	}
	var best string
	for _, g := range callerGroups {
		if _, ok := srcSet[g]; !ok {
			continue
		}
		if best == "" || g < best {
			best = g
		}
	}
	return best
}

func anyGroupMatches(sourceGroups []string, callerSet map[string]struct{}) bool {
	for _, g := range sourceGroups {
		if _, ok := callerSet[g]; ok {
			return true
		}
	}
	return false
}

// isUncapped reports whether a policy has any enabled cap with a
// positive limit value. Mirrors the eval functions' guards: a policy
// with token_limit.enabled=true but every cap value at 0 still
// counts as uncapped because the eval would query nothing and bind
// nothing.
func isUncapped(p *types.Policy) bool {
	tl := p.Limits.TokenLimit
	if tl.Enabled && tl.WindowSeconds > 0 && (tl.GroupCap > 0 || tl.UserCap > 0) {
		return false
	}
	bl := p.Limits.BudgetLimit
	if bl.Enabled && bl.WindowSeconds > 0 && (bl.GroupCapUsd > 0 || bl.UserCapUsd > 0) {
		return false
	}
	return true
}

// groupCapTokens returns the policy's group-token cap when the token
// limit is enabled, zero otherwise. Drives the primary "bigger pool
// first" sort.
func groupCapTokens(p *types.Policy) int64 {
	if p.Limits.TokenLimit.Enabled {
		return p.Limits.TokenLimit.GroupCap
	}
	return 0
}

// groupCapBudgetUsd returns the policy's group-budget cap in USD
// when the budget limit is enabled, zero otherwise. Secondary sort
// key after token group cap so budget-only policies still order
// predictably.
func groupCapBudgetUsd(p *types.Policy) float64 {
	if p.Limits.BudgetLimit.Enabled {
		return p.Limits.BudgetLimit.GroupCapUsd
	}
	return 0
}

// userCapTokens returns the policy's per-user token cap when the
// token limit is enabled, zero otherwise. Tertiary sort key, used
// when group caps tie or are absent.
func userCapTokens(p *types.Policy) int64 {
	if p.Limits.TokenLimit.Enabled {
		return p.Limits.TokenLimit.UserCap
	}
	return 0
}

// userCapBudgetUsd returns the policy's per-user budget cap in USD
// when the budget limit is enabled, zero otherwise. Quaternary sort
// key for budget-only policies whose group caps tie or are absent.
func userCapBudgetUsd(p *types.Policy) float64 {
	if p.Limits.BudgetLimit.Enabled {
		return p.Limits.BudgetLimit.UserCapUsd
	}
	return 0
}

func sliceContains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// mockManager fallback so tests that don't care about selection still
// compile.
func (*mockManager) SelectPolicyForRequest(_ context.Context, _ PolicySelectionInput) (*PolicySelectionResult, error) {
	return &PolicySelectionResult{Allow: true}, nil
}
