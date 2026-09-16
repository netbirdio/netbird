package agentnetwork

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// GetAgentConfigForUser returns the Agent Network setup the calling user's
// groups authorize. It deliberately performs no role permission check:
// the result is scoped to the caller's own groups, which is strictly
// tighter than any role gate, so every authenticated user (any role) may
// read it. The group source matches enforcement: the proxy authorizes
// each Agent Network request against the calling user's groups as well —
// session validation resolves them from the same user record's
// auto-groups — so this answer and the proxy's verdict are computed from
// the same memberships.
func (m *managerImpl) GetAgentConfigForUser(ctx context.Context, accountID, userID string) (*types.AgentConfig, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return m.agentConfigForGroups(ctx, accountID, user.AutoGroups)
}

// agentConfigForGroups computes the effective Agent Network setup for
// a set of caller groups: the account endpoint plus, per authorized
// provider, the effective model set. It mirrors what the proxy enforces
// at request time — the policy filter matches filterApplicablePolicies,
// the model logic matches policyPermitsModel, and orphan providers
// (enabled but referenced by no applicable policy) are omitted just like
// the router synthesizer omits them — so the answer never advertises
// anything the proxy would refuse.
//
// Configured tracks the account, not the caller: once the account has an
// endpoint every member gets it, with Providers empty for those no policy
// covers yet. The dashboard shows each user the same connection config
// regardless of role, and an empty provider list tells them to ask for
// access. Only the account having no Agent Network at all reads as not
// configured. Providers stays caller-scoped either way — the endpoint on
// its own authorizes nothing, and the proxy still refuses every request
// no policy permits.
func (m *managerImpl) agentConfigForGroups(ctx context.Context, accountID string, groupIDs []string) (*types.AgentConfig, error) {
	notConfigured := &types.AgentConfig{Providers: []types.AgentConfigProvider{}}

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

	authorized, applicable, err := m.authorizedProvidersForGroups(ctx, accountID, groupIDs)
	if err != nil {
		return nil, err
	}

	out := &types.AgentConfig{
		Configured: true,
		Endpoint:   "https://" + settings.Endpoint(),
		Providers:  make([]types.AgentConfigProvider, 0, len(authorized)),
	}
	if len(authorized) == 0 {
		return out, nil
	}

	var guardrailsByID map[string]*types.Guardrail
	if anyPolicyHasGuardrails(applicable) {
		guardrailsByID, err = m.loadGuardrailsByID(ctx, accountID)
		if err != nil {
			return nil, err
		}
	}
	for _, p := range authorized {
		allAllowed, models := effectiveModelsForProvider(p, policiesForProvider(applicable, p.ID), guardrailsByID)
		flavor := ""
		if entry, ok := catalog.Lookup(p.ProviderID); ok {
			flavor = entry.ParserID
		}
		out.Providers = append(out.Providers, types.AgentConfigProvider{
			Name:             p.Name,
			CatalogID:        p.ProviderID,
			APIFlavor:        flavor,
			AllModelsAllowed: allAllowed,
			Models:           models,
		})
	}
	return out, nil
}

// authorizedProvidersForGroups returns the enabled providers referenced
// by at least one enabled policy whose source groups intersect groupIDs —
// the providers the caller's own policies authorize — in created_at order
// with ID tiebreak, the same deterministic order the router synthesizer
// presents. The applicable policies come back alongside so callers that
// need per-provider policy context (the setup's model computation) don't
// re-filter. Both the self-service setup answer and the caller-scoped
// provider list are built from this selection, so what the dashboard
// offers and what the proxy enforces never diverge.
func (m *managerImpl) authorizedProvidersForGroups(ctx context.Context, accountID string, groupIDs []string) ([]*types.Provider, []*types.Policy, error) {
	policies, err := m.store.GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("list account policies: %w", err)
	}
	applicable := filterPoliciesByGroups(policies, groupIDs)
	if len(applicable) == 0 {
		return nil, nil, nil
	}

	providers, err := m.store.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("list account providers: %w", err)
	}

	// filterEnabledProviders carries the enabled filter and the
	// created_at/ID order shared with the router synthesizer.
	enabled := filterEnabledProviders(providers)
	authorized := make([]*types.Provider, 0, len(enabled))
	for _, p := range enabled {
		if len(policiesForProvider(applicable, p.ID)) == 0 {
			continue
		}
		authorized = append(authorized, p)
	}
	return authorized, applicable, nil
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
// Allowlist entries and declared ids both compare through the canonical
// id the proxy's parser emits, so an allowlist may hold either form: the
// raw declared id the dashboard's picker copies from the provider, or
// the stripped id the parser matches at request time.
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
				key := canonicalModelKey(provider.ProviderID, model)
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
		// Compare through the canonical id the proxy's parser emits — a
		// Bedrock declaration may carry the region/version form
		// ("eu.anthropic.claude-...-v1:0") that the parser strips at
		// request time, and the raw forms would never intersect. The
		// declared id itself is what gets advertised, matching the
		// router's route claim.
		if _, ok := seen[canonicalModelKey(provider.ProviderID, id)]; ok {
			out = append(out, id)
		}
	}
	return false, out
}

// canonicalModelKey builds the compare key for a model id: lowercased,
// trimmed, and canonicalized through the provider-aware normalization the
// proxy's parser applies. Lowercase/trim comes FIRST — the path-style
// strippers anchor on a lowercase id's tail, so a trailing space or a
// case-variant geography/version would otherwise survive into the key.
func canonicalModelKey(catalogProviderID, id string) string {
	return normaliseModelID(normalizePricingModelID(catalogProviderID, normaliseModelID(id)))
}

// providerModelsByID maps effective model ids (as effectiveModelsForProvider
// returns them) back onto the operator's declared entries, keeping the
// declared casing and prices. With no operator declaration the ids are the
// allowlist union and have no declared entry to map to, so bare entries are
// synthesized — the router claims every model in that case, so those ids are
// reachable and belong in the answer.
func providerModelsByID(provider *types.Provider, ids []string) []types.ProviderModel {
	if len(provider.Models) == 0 {
		out := make([]types.ProviderModel, 0, len(ids))
		for _, id := range ids {
			out = append(out, types.ProviderModel{ID: id})
		}
		return out
	}
	keep := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		keep[normaliseModelID(id)] = struct{}{}
	}
	out := make([]types.ProviderModel, 0, len(ids))
	for _, m := range provider.Models {
		if _, ok := keep[normaliseModelID(m.ID)]; ok {
			out = append(out, m)
		}
	}
	return out
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

// GetAgentConfigForUser on the mock manager reports "not configured" so tests
// that don't care about setup still compile.
func (*mockManager) GetAgentConfigForUser(_ context.Context, _, _ string) (*types.AgentConfig, error) {
	return &types.AgentConfig{Providers: []types.AgentConfigProvider{}}, nil
}
