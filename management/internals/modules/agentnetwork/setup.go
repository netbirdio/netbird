package agentnetwork

import (
	"context"
	"fmt"
	"sort"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// GetSetupForUser returns the Agent Network setup the calling user's
// groups authorize. It deliberately performs no role permission check:
// the result is scoped to the caller's own groups, which is strictly
// tighter than any role gate, so every authenticated user (any role) may
// read it. Peers and users carry the same groups, so the answer matches
// what the proxy enforces for the caller's machines at request time.
func (m *managerImpl) GetSetupForUser(ctx context.Context, accountID, userID string) (*types.EffectiveSetup, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return m.effectiveSetupForGroups(ctx, accountID, user.AutoGroups)
}

// ListConsumptionForUser returns the caller's own consumption counters:
// the user-dimension rows recorded for userID. Caller-scoped by design —
// no role permission check, mirroring GetSetupForUser.
func (m *managerImpl) ListConsumptionForUser(ctx context.Context, accountID, userID string) ([]*types.Consumption, error) {
	rows, err := m.store.ListAgentNetworkConsumption(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	own := make([]*types.Consumption, 0)
	for _, row := range rows {
		if row.DimensionKind == types.DimensionUser && row.DimensionID == userID {
			own = append(own, row)
		}
	}
	return own, nil
}

// effectiveSetupForGroups computes the effective Agent Network setup for
// a set of caller groups: the account endpoint plus, per authorized
// provider, the effective model set. It mirrors what the proxy enforces
// at request time — the policy filter matches filterApplicablePolicies,
// the model logic matches policyPermitsModel, and orphan providers
// (enabled but referenced by no applicable policy) are omitted just like
// the router synthesizer omits them — so the answer never advertises
// anything the proxy would refuse.
//
// Every "nothing available" shape returns Configured=false rather than
// an error, and "account not set up" is indistinguishable from "caller
// has no access" by design: the response must not leak what exists for
// others.
func (m *managerImpl) effectiveSetupForGroups(ctx context.Context, accountID string, groupIDs []string) (*types.EffectiveSetup, error) {
	notConfigured := &types.EffectiveSetup{Providers: []types.EffectiveProvider{}}

	settings, err := m.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	switch {
	case err == nil:
	case isNotFound(err):
		return notConfigured, nil
	default:
		return nil, fmt.Errorf("get agent network settings: %w", err)
	}
	if settings.Endpoint() == "" {
		return notConfigured, nil
	}

	policies, err := m.store.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("list account policies: %w", err)
	}
	applicable := filterPoliciesByGroups(policies, groupIDs)
	if len(applicable) == 0 {
		return notConfigured, nil
	}

	providers, err := m.store.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("list account providers: %w", err)
	}

	var guardrailsByID map[string]*types.Guardrail
	if anyPolicyHasGuardrails(applicable) {
		guardrailsByID, err = m.loadGuardrailsByID(ctx, accountID)
		if err != nil {
			return nil, err
		}
	}

	authorized := make([]*types.Provider, 0, len(providers))
	for _, p := range providers {
		if p == nil || !p.Enabled {
			continue
		}
		if len(policiesForProvider(applicable, p.ID)) == 0 {
			continue
		}
		authorized = append(authorized, p)
	}
	if len(authorized) == 0 {
		return notConfigured, nil
	}
	// created_at order, ID tiebreak — same deterministic order the router
	// synthesizer presents.
	sort.SliceStable(authorized, func(i, j int) bool {
		if !authorized[i].CreatedAt.Equal(authorized[j].CreatedAt) {
			return authorized[i].CreatedAt.Before(authorized[j].CreatedAt)
		}
		return authorized[i].ID < authorized[j].ID
	})

	out := &types.EffectiveSetup{
		Configured: true,
		Endpoint:   "https://" + settings.Endpoint(),
		Providers:  make([]types.EffectiveProvider, 0, len(authorized)),
	}
	for _, p := range authorized {
		allAllowed, models := effectiveModelsForProvider(p, policiesForProvider(applicable, p.ID), guardrailsByID)
		flavor := ""
		if entry, ok := catalog.Lookup(p.ProviderID); ok {
			flavor = entry.ParserID
		}
		out.Providers = append(out.Providers, types.EffectiveProvider{
			Name:             p.Name,
			CatalogID:        p.ProviderID,
			APIFlavor:        flavor,
			AllModelsAllowed: allAllowed,
			Models:           models,
		})
	}
	return out, nil
}

// filterPoliciesByGroups returns the enabled policies whose SourceGroups
// intersect the caller's groups. Same group matching as
// filterApplicablePolicies, without the per-provider filter — the setup
// answer spans every provider the caller can reach.
func filterPoliciesByGroups(policies []*types.Policy, groupIDs []string) []*types.Policy {
	groupSet := make(map[string]struct{}, len(groupIDs))
	for _, g := range groupIDs {
		if g != "" {
			groupSet[g] = struct{}{}
		}
	}
	out := make([]*types.Policy, 0, len(policies))
	for _, p := range policies {
		if p == nil || !p.Enabled {
			continue
		}
		if !anyGroupMatches(p.SourceGroups, groupSet) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// policiesForProvider returns the subset of policies targeting the
// provider, order preserved.
func policiesForProvider(policies []*types.Policy, providerID string) []*types.Policy {
	out := make([]*types.Policy, 0, len(policies))
	for _, p := range policies {
		if sliceContains(p.DestinationProviderIDs, providerID) {
			out = append(out, p)
		}
	}
	return out
}

// effectiveModelsForProvider derives the caller's effective model set for
// one provider from the applicable policies that target it, mirroring
// policyPermitsModel: a policy with no allowlist-enabled guardrail is
// unrestricted, and one unrestricted policy makes the whole provider
// unrestricted (the proxy would admit any model through it). Otherwise
// the union of the policies' allowlists applies, intersected with the
// provider's declared models when the operator declared any — the router
// only claims declared models, so an allowlisted-but-undeclared model is
// unreachable and must not be advertised. With no declared models the
// router claims every model, so the allowlist union stands alone.
func effectiveModelsForProvider(provider *types.Provider, policies []*types.Policy, guardrailsByID map[string]*types.Guardrail) (bool, []string) {
	restricted := true
	union := make([]string, 0)
	seen := make(map[string]struct{})
	for _, p := range policies {
		policyRestricted := false
		for _, gID := range p.GuardrailIDs {
			g, ok := guardrailsByID[gID]
			if !ok || g == nil || !g.Checks.ModelAllowlist.Enabled {
				continue
			}
			policyRestricted = true
			for _, model := range g.Checks.ModelAllowlist.Models {
				key := normaliseModelID(model)
				if key == "" {
					continue
				}
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				union = append(union, key)
			}
		}
		if !policyRestricted {
			restricted = false
		}
	}

	declared := declaredModelIDs(provider)
	if !restricted {
		return true, declared
	}
	if len(provider.Models) == 0 {
		// No operator declaration: the router claims every model, so the
		// allowlist union is the effective set as-is.
		return false, union
	}
	out := make([]string, 0, len(declared))
	for _, id := range declared {
		if _, ok := seen[normaliseModelID(id)]; ok {
			out = append(out, id)
		}
	}
	return false, out
}

// declaredModelIDs returns the models a provider exposes: the operator's
// curated list when present, otherwise the catalog entry's models (an
// empty operator list means "all catalog models"). Gateway/custom catalog
// entries declare no models, so the result may be empty.
func declaredModelIDs(provider *types.Provider) []string {
	if ids := providerModelIDs(provider); len(ids) > 0 {
		return ids
	}
	entry, ok := catalog.Lookup(provider.ProviderID)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(entry.Models))
	for _, m := range entry.Models {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out
}

// GetSetupForUser on the mock manager reports "not configured" so tests
// that don't care about setup still compile.
func (*mockManager) GetSetupForUser(_ context.Context, _, _ string) (*types.EffectiveSetup, error) {
	return &types.EffectiveSetup{Providers: []types.EffectiveProvider{}}, nil
}

// ListConsumptionForUser on the mock manager returns no rows.
func (*mockManager) ListConsumptionForUser(_ context.Context, _, _ string) ([]*types.Consumption, error) {
	return nil, nil
}
