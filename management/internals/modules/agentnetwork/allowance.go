package agentnetwork

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// fillAllowances sets each provider's Allowance for the calling principal.
// It runs the selector's own steps (applicable policies, account ceiling,
// candidate scoring) against one batched consumption read, so Exhausted
// matches what SelectPolicyForRequest would answer. The model gate is
// skipped: no request model exists here, and its empty-model rule would
// report every allowlisted provider as exhausted.
func (m *managerImpl) fillAllowances(ctx context.Context, accountID, userID string, groupIDs []string, providers []types.AgentConfigProvider) error {
	if len(providers) == 0 {
		return nil
	}
	now := time.Now().UTC()

	rules, err := m.store.GetAccountAgentNetworkBudgetRules(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("list account budget rules: %w", err)
	}
	policies, err := m.store.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("list account policies: %w", err)
	}

	base := PolicySelectionInput{AccountID: accountID, UserID: userID, GroupIDs: groupIDs}
	candidates := make([][]*types.Policy, len(providers))
	var all []*types.Policy
	for i, p := range providers {
		in := base
		in.ProviderID = p.ID
		candidates[i] = filterApplicablePolicies(policies, in)
		all = append(all, candidates[i]...)
	}

	cache, err := m.prefetchConsumption(ctx, base, rules, all, now)
	if err != nil {
		return err
	}

	ruleLimits := accountRuleLimits(base, rules, cache, now)
	accountDeny, _, _ := checkAccountBudget(base, rules, cache, now)
	for i := range providers {
		a := providerAllowance(base, candidates[i], cache, now, ruleLimits)
		if accountDeny {
			a.Exhausted = true
		}
		providers[i].Allowance = a
	}

	return m.fillGroupNames(ctx, accountID, providers)
}

// providerAllowance builds one provider's allowance from its applicable
// policies. An uncapped policy wins selection outright and books nothing
// against policy windows, so once one applies the policy caps no longer bind
// and only the account rules are listed.
func providerAllowance(in PolicySelectionInput, candidates []*types.Policy, cache consumptionCache, now time.Time, ruleLimits []types.AllowanceLimit) *types.ProviderAllowance {
	a := &types.ProviderAllowance{Limits: append([]types.AllowanceLimit(nil), ruleLimits...)}

	uncapped := len(candidates) == 0
	for _, p := range candidates {
		if isUncapped(p) {
			uncapped = true
		}
	}
	a.Unlimited = uncapped && len(ruleLimits) == 0
	if uncapped {
		return a
	}

	for _, p := range candidates {
		attr := lowestIntersect(p.SourceGroups, in.GroupIDs)
		usages := append(
			tokenCapUsages(cache, in.AccountID, in.UserID, attr, p.Limits.TokenLimit, now),
			budgetCapUsages(cache, in.AccountID, in.UserID, attr, p.Limits.BudgetLimit, now)...,
		)
		for _, u := range usages {
			a.Limits = append(a.Limits, allowanceLimit(types.AllowanceSourcePolicy, p.ID, p.Name, u))
		}
	}

	if scored, _, _ := scoreCandidates(in, candidates, cache, now); len(scored) == 0 {
		a.Exhausted = true
	}
	return a
}

// accountRuleLimits lists the caps of every account rule that binds the
// caller. Rules apply across providers, so every provider carries them.
func accountRuleLimits(in PolicySelectionInput, rules []*types.AccountBudgetRule, cache consumptionCache, now time.Time) []types.AllowanceLimit {
	var out []types.AllowanceLimit
	for _, r := range rules {
		if r == nil || !r.Enabled || !budgetRuleApplies(r, in) {
			continue
		}
		attr := lowestIntersect(r.TargetGroups, in.GroupIDs)
		usages := append(
			tokenCapUsages(cache, in.AccountID, in.UserID, attr, r.Limits.TokenLimit, now),
			budgetCapUsages(cache, in.AccountID, in.UserID, attr, r.Limits.BudgetLimit, now)...,
		)
		for _, u := range usages {
			out = append(out, allowanceLimit(types.AllowanceSourceAccountRule, r.ID, r.Name, u))
		}
	}
	return out
}

func allowanceLimit(source types.AllowanceSource, id, name string, u capUsage) types.AllowanceLimit {
	return types.AllowanceLimit{
		Source:     source,
		SourceID:   id,
		SourceName: name,
		Unit:       u.unit,
		Scope:      u.scope,
		GroupID:    u.groupID,
		Cap:        u.cap,
		Used:       u.used,
		ResetsAt:   u.windowStart.Add(time.Duration(u.windowSeconds) * time.Second),
	}
}

// fillGroupNames resolves the group names of group-scoped limits in one read.
func (m *managerImpl) fillGroupNames(ctx context.Context, accountID string, providers []types.AgentConfigProvider) error {
	var ids []string
	for _, p := range providers {
		for _, l := range p.Allowance.Limits {
			if l.GroupID != "" {
				ids = append(ids, l.GroupID)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	groups, err := m.store.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, ids)
	if err != nil {
		return fmt.Errorf("get limit groups: %w", err)
	}
	for _, p := range providers {
		for i := range p.Allowance.Limits {
			if g, ok := groups[p.Allowance.Limits[i].GroupID]; ok && g != nil {
				p.Allowance.Limits[i].GroupName = g.Name
			}
		}
	}
	return nil
}
