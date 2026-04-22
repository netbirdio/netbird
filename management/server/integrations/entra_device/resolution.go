package entra_device

import (
	"sort"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
)

// ResolveMapping evaluates the configured mappings against the device's
// transitive Entra group membership, returning the effective configuration to
// apply to the new peer. It is the single place where "what happens when a
// device is in multiple enrolment groups?" is answered.
//
// The function is deterministic and side-effect free so it can be unit-tested
// in isolation.
//
// Contract:
//   - revoked or expired mappings NEVER contribute.
//   - wildcards (mapping.EntraGroupID == "*" / "") match any device.
//   - strict_priority picks exactly one mapping: lowest Priority, then lowest
//     mapping ID for determinism.
//   - union merges every matched mapping: AutoGroups are set-unioned,
//     Ephemeral is OR'd (most restrictive), AllowExtraDNSLabels is AND'd
//     (most restrictive), ExpiresAt is the min of non-nil values.
//   - when nothing matches, the caller is expected to inspect the returned
//     Error to distinguish `no_mapping_matched` vs `all_mappings_revoked`
//     vs `all_mappings_expired` and may also apply a tenant-only fallback.
func ResolveMapping(
	auth *types.EntraDeviceAuth,
	all []*types.EntraDeviceAuthMapping,
	deviceGroupIDs []string,
) (*ResolvedMapping, *Error) {
	if auth == nil {
		return nil, NewError(CodeIntegrationNotFound, "integration config missing", nil)
	}

	// Build a lookup for the device's groups.
	inDeviceGroup := make(map[string]struct{}, len(deviceGroupIDs))
	for _, g := range deviceGroupIDs {
		inDeviceGroup[g] = struct{}{}
	}

	// Separate mappings that *could* have matched by group from those filtered
	// out by revocation/expiry so we can return a precise error code.
	var (
		candidates    []*types.EntraDeviceAuthMapping
		sawRevoked    bool
		sawExpired    bool
		sawAnyMatcher bool // any mapping whose group matched (even if filtered)
	)
	for _, m := range all {
		matched := m.IsWildcard()
		if !matched {
			if _, ok := inDeviceGroup[m.EntraGroupID]; ok {
				matched = true
			}
		}
		if !matched {
			continue
		}
		sawAnyMatcher = true

		if m.Revoked {
			sawRevoked = true
			continue
		}
		if m.IsExpired() {
			sawExpired = true
			continue
		}
		candidates = append(candidates, m)
	}

	if len(candidates) == 0 {
		if !sawAnyMatcher {
			// Apply tenant-only fallback if admin opted in.
			if auth.AllowTenantOnlyFallback && len(auth.FallbackAutoGroups) > 0 {
				return &ResolvedMapping{
					AutoGroups:        append([]string{}, auth.FallbackAutoGroups...),
					MatchedMappingIDs: nil,
					ResolutionMode:    "tenant_fallback",
				}, nil
			}
			return nil, NewError(CodeNoMappingMatched,
				"device is not a member of any mapped Entra group", nil)
		}
		if sawRevoked && !sawExpired {
			return nil, NewError(CodeAllMappingsRevoked,
				"every Entra group mapping that matches this device is revoked", nil)
		}
		if sawExpired && !sawRevoked {
			return nil, NewError(CodeAllMappingsExpired,
				"every Entra group mapping that matches this device is expired", nil)
		}
		// Both sawRevoked and sawExpired were true. Report the more specific
		// of the two (revoked is an admin action, expired is a time event).
		return nil, NewError(CodeAllMappingsRevoked,
			"no eligible Entra group mapping (all either revoked or expired)", nil)
	}

	switch auth.ResolutionOrDefault() {
	case types.MappingResolutionUnion:
		return resolveUnion(candidates), nil
	default:
		return resolveStrictPriority(candidates), nil
	}
}

// resolveStrictPriority picks the single mapping with the lowest Priority.
// Ties broken by ID ascending.
func resolveStrictPriority(candidates []*types.EntraDeviceAuthMapping) *ResolvedMapping {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].ID < candidates[j].ID
	})
	winner := candidates[0]
	r := &ResolvedMapping{
		AutoGroups:          append([]string{}, winner.AutoGroups...),
		Ephemeral:           winner.Ephemeral,
		AllowExtraDNSLabels: winner.AllowExtraDNSLabels,
		MatchedMappingIDs:   []string{winner.ID},
		ResolutionMode:      string(types.MappingResolutionStrictPriority),
	}
	if winner.ExpiresAt != nil {
		t := *winner.ExpiresAt
		r.ExpiresAt = &t
	}
	return r
}

// resolveUnion merges every matched mapping into a single effective config.
func resolveUnion(candidates []*types.EntraDeviceAuthMapping) *ResolvedMapping {
	// Deterministic order so MatchedMappingIDs is stable.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority < candidates[j].Priority
		}
		return candidates[i].ID < candidates[j].ID
	})

	seen := make(map[string]struct{})
	out := &ResolvedMapping{
		// AllowExtraDNSLabels starts as true (AND identity) but only
		// if we later observe at least one mapping; handled below.
		ResolutionMode: string(types.MappingResolutionUnion),
	}
	allowLabels := true

	for i, m := range candidates {
		out.MatchedMappingIDs = append(out.MatchedMappingIDs, m.ID)
		for _, g := range m.AutoGroups {
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}
			out.AutoGroups = append(out.AutoGroups, g)
		}
		// Ephemeral: OR
		if m.Ephemeral {
			out.Ephemeral = true
		}
		// AllowExtraDNSLabels: AND
		if !m.AllowExtraDNSLabels {
			allowLabels = false
		}
		// ExpiresAt: min of non-nil
		if m.ExpiresAt != nil {
			t := *m.ExpiresAt
			if out.ExpiresAt == nil || t.Before(*out.ExpiresAt) {
				out.ExpiresAt = &t
			}
		}

		// Defensive fallback: if nobody set any AutoGroups, the resulting
		// peer would end up ungrouped. Surface that explicitly in tests.
		if i == len(candidates)-1 && len(out.AutoGroups) == 0 {
			out.AutoGroups = []string{}
		}
	}
	out.AllowExtraDNSLabels = allowLabels
	return out
}

// Now returns the current UTC time; overridable in tests.
var Now = func() time.Time { return time.Now().UTC() }
