package entra_device

import (
	"sort"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
)

// ResolveMapping evaluates the configured mappings against the device's
// transitive Entra group membership, returning the effective configuration to
// apply to the new peer.
//
// Contract:
//   - revoked or expired mappings NEVER contribute.
//   - wildcards (mapping.EntraGroupID == "*" / "") match any device.
//   - strict_priority picks exactly one mapping: lowest Priority, then lowest
//     mapping ID for determinism.
//   - union merges every matched mapping: AutoGroups are set-unioned,
//     Ephemeral is OR'd (most restrictive), AllowExtraDNSLabels is AND'd
//     (most restrictive), ExpiresAt is the min of non-nil values.
//   - when nothing matches, the caller gets a precise error code
//     (`no_mapping_matched` / `all_mappings_revoked` / `all_mappings_expired`)
//     or the tenant-only fallback if admin opted in.
func ResolveMapping(
	auth *types.EntraDeviceAuth,
	all []*types.EntraDeviceAuthMapping,
	deviceGroupIDs []string,
) (*ResolvedMapping, *Error) {
	if auth == nil {
		return nil, NewError(CodeIntegrationNotFound, "integration config missing", nil)
	}

	candidates, summary := filterCandidates(all, deviceGroupIDs)
	if len(candidates) == 0 {
		return handleNoCandidates(auth, summary)
	}

	if auth.ResolutionOrDefault() == types.MappingResolutionUnion {
		return resolveUnion(candidates), nil
	}
	return resolveStrictPriority(candidates), nil
}

// matchSummary tracks why a mapping-candidate set came back empty.
type matchSummary struct {
	sawAnyMatcher bool
	sawRevoked    bool
	sawExpired    bool
}

// filterCandidates walks all mappings and selects the ones that both match
// the device's transitive group membership and are currently eligible.
func filterCandidates(
	all []*types.EntraDeviceAuthMapping,
	deviceGroupIDs []string,
) ([]*types.EntraDeviceAuthMapping, matchSummary) {
	inDeviceGroup := make(map[string]struct{}, len(deviceGroupIDs))
	for _, g := range deviceGroupIDs {
		inDeviceGroup[g] = struct{}{}
	}

	var (
		candidates []*types.EntraDeviceAuthMapping
		sum        matchSummary
	)
	for _, m := range all {
		if !mappingMatchesDevice(m, inDeviceGroup) {
			continue
		}
		sum.sawAnyMatcher = true

		if m.Revoked {
			sum.sawRevoked = true
			continue
		}
		if m.IsExpired() {
			sum.sawExpired = true
			continue
		}
		candidates = append(candidates, m)
	}
	return candidates, sum
}

func mappingMatchesDevice(m *types.EntraDeviceAuthMapping, inDeviceGroup map[string]struct{}) bool {
	if m.IsWildcard() {
		return true
	}
	_, ok := inDeviceGroup[m.EntraGroupID]
	return ok
}

// handleNoCandidates produces the outcome when there are no eligible
// mappings: tenant-only fallback, or the most specific error code that
// describes why.
func handleNoCandidates(auth *types.EntraDeviceAuth, sum matchSummary) (*ResolvedMapping, *Error) {
	if !sum.sawAnyMatcher {
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
	switch {
	case sum.sawRevoked && !sum.sawExpired:
		return nil, NewError(CodeAllMappingsRevoked,
			"every Entra group mapping that matches this device is revoked", nil)
	case sum.sawExpired && !sum.sawRevoked:
		return nil, NewError(CodeAllMappingsExpired,
			"every Entra group mapping that matches this device is expired", nil)
	default:
		// Both seen — revoked (admin action) wins as the more specific signal.
		return nil, NewError(CodeAllMappingsRevoked,
			"no eligible Entra group mapping (all either revoked or expired)", nil)
	}
}

// resolveStrictPriority picks the single mapping with the lowest Priority.
// Ties broken by ID ascending.
func resolveStrictPriority(candidates []*types.EntraDeviceAuthMapping) *ResolvedMapping {
	sortByPriorityThenID(candidates)
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
	sortByPriorityThenID(candidates)

	seen := make(map[string]struct{})
	out := &ResolvedMapping{ResolutionMode: string(types.MappingResolutionUnion)}
	// AllowExtraDNSLabels starts at the AND identity; flipped to false by
	// the first denying mapping encountered.
	allowLabels := true

	for _, m := range candidates {
		out.MatchedMappingIDs = append(out.MatchedMappingIDs, m.ID)
		appendNewAutoGroups(out, m.AutoGroups, seen)
		if m.Ephemeral {
			out.Ephemeral = true
		}
		if !m.AllowExtraDNSLabels {
			allowLabels = false
		}
		mergeMinExpiry(out, m.ExpiresAt)
	}

	out.AllowExtraDNSLabels = allowLabels
	if out.AutoGroups == nil {
		out.AutoGroups = []string{}
	}
	return out
}

func sortByPriorityThenID(ms []*types.EntraDeviceAuthMapping) {
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].Priority != ms[j].Priority {
			return ms[i].Priority < ms[j].Priority
		}
		return ms[i].ID < ms[j].ID
	})
}

func appendNewAutoGroups(out *ResolvedMapping, src []string, seen map[string]struct{}) {
	for _, g := range src {
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out.AutoGroups = append(out.AutoGroups, g)
	}
}

func mergeMinExpiry(out *ResolvedMapping, candidate *time.Time) {
	if candidate == nil {
		return
	}
	t := *candidate
	if out.ExpiresAt == nil || t.Before(*out.ExpiresAt) {
		out.ExpiresAt = &t
	}
}

// Now returns the current UTC time; overridable in tests.
var Now = func() time.Time { return time.Now().UTC() }
