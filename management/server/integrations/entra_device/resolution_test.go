package entra_device

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func mkMapping(id, group string, prio int, auto []string, ephemeral, allowLabels bool) *types.EntraDeviceAuthMapping {
	return &types.EntraDeviceAuthMapping{
		ID:                  id,
		EntraGroupID:        group,
		Priority:            prio,
		AutoGroups:          append([]string(nil), auto...),
		Ephemeral:           ephemeral,
		AllowExtraDNSLabels: allowLabels,
	}
}

func TestResolveMapping_NoCandidates_NoMatch(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	mappings := []*types.EntraDeviceAuthMapping{
		mkMapping("m1", "GROUP_A", 10, []string{"ng-a"}, false, true),
	}
	_, err := ResolveMapping(auth, mappings, []string{"GROUP_UNRELATED"})
	require.NotNil(t, err)
	assert.Equal(t, CodeNoMappingMatched, err.Code)
}

func TestResolveMapping_TenantFallback(t *testing.T) {
	auth := &types.EntraDeviceAuth{
		AllowTenantOnlyFallback: true,
		FallbackAutoGroups:      []string{"fallback"},
	}
	// Device in no mapped group; fallback should kick in.
	r, err := ResolveMapping(auth, nil, []string{"ANY"})
	require.Nil(t, err)
	assert.Equal(t, []string{"fallback"}, r.AutoGroups)
	assert.Equal(t, "tenant_fallback", r.ResolutionMode)
}

func TestResolveMapping_StrictPriority_LowestWins(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	mappings := []*types.EntraDeviceAuthMapping{
		mkMapping("m-high", "GROUP_A", 100, []string{"ng-corp"}, false, true),
		mkMapping("m-low", "GROUP_B", 10, []string{"ng-finance"}, false, false),
	}
	r, err := ResolveMapping(auth, mappings, []string{"GROUP_A", "GROUP_B"})
	require.Nil(t, err)
	assert.Equal(t, []string{"m-low"}, r.MatchedMappingIDs)
	assert.Equal(t, []string{"ng-finance"}, r.AutoGroups)
	assert.False(t, r.AllowExtraDNSLabels)
}

func TestResolveMapping_StrictPriority_TieBreakByID(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	// Two mappings with identical Priority; lowest ID should win.
	mappings := []*types.EntraDeviceAuthMapping{
		mkMapping("m-z", "GROUP_A", 10, []string{"ng-z"}, false, true),
		mkMapping("m-a", "GROUP_B", 10, []string{"ng-a"}, false, true),
	}
	r, err := ResolveMapping(auth, mappings, []string{"GROUP_A", "GROUP_B"})
	require.Nil(t, err)
	assert.Equal(t, []string{"m-a"}, r.MatchedMappingIDs)
}

func TestResolveMapping_Union_MergesAutoGroupsAndFlags(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionUnion}
	exp := time.Now().Add(1 * time.Hour)
	expLater := time.Now().Add(30 * 24 * time.Hour)

	mappings := []*types.EntraDeviceAuthMapping{
		// ephemeral=false, allowLabels=true, later expiry
		{
			ID: "m-finance", EntraGroupID: "Finance", Priority: 10,
			AutoGroups: []string{"finance-vpn", "finance-apps"},
			Ephemeral:  false, AllowExtraDNSLabels: true,
			ExpiresAt: &expLater,
		},
		// ephemeral=true (OR dominates), allowLabels=false (AND dominates)
		{
			ID: "m-devs", EntraGroupID: "Developers", Priority: 20,
			AutoGroups: []string{"dev-sandbox", "finance-apps"}, // intentional dup
			Ephemeral:  true, AllowExtraDNSLabels: false,
			ExpiresAt: &exp, // earliest
		},
		// base tier, higher priority number, still unions
		{
			ID: "m-corp", EntraGroupID: "*", Priority: 100,
			AutoGroups: []string{"corp-baseline"},
			Ephemeral:  false, AllowExtraDNSLabels: true,
		},
	}
	r, err := ResolveMapping(auth, mappings, []string{"Finance", "Developers"})
	require.Nil(t, err)

	// All three should contribute (wildcard always matches).
	assert.ElementsMatch(t, []string{"m-finance", "m-devs", "m-corp"}, r.MatchedMappingIDs)

	// Union, deduped.
	groups := append([]string{}, r.AutoGroups...)
	sort.Strings(groups)
	assert.Equal(t, []string{"corp-baseline", "dev-sandbox", "finance-apps", "finance-vpn"}, groups)

	// Ephemeral OR -> true.
	assert.True(t, r.Ephemeral)
	// AllowExtraDNSLabels AND -> false.
	assert.False(t, r.AllowExtraDNSLabels)
	// ExpiresAt min -> exp (earliest).
	require.NotNil(t, r.ExpiresAt)
	assert.WithinDuration(t, exp, *r.ExpiresAt, time.Second)
}

func TestResolveMapping_AllRevoked(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	m := mkMapping("m1", "GROUP_A", 10, []string{"ng-a"}, false, true)
	m.Revoked = true
	_, err := ResolveMapping(auth, []*types.EntraDeviceAuthMapping{m}, []string{"GROUP_A"})
	require.NotNil(t, err)
	assert.Equal(t, CodeAllMappingsRevoked, err.Code)
}

func TestResolveMapping_AllExpired(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	past := time.Now().Add(-1 * time.Hour)
	m := mkMapping("m1", "GROUP_A", 10, []string{"ng-a"}, false, true)
	m.ExpiresAt = &past
	_, err := ResolveMapping(auth, []*types.EntraDeviceAuthMapping{m}, []string{"GROUP_A"})
	require.NotNil(t, err)
	assert.Equal(t, CodeAllMappingsExpired, err.Code)
}

func TestResolveMapping_RevokedDoesNotWinPriority(t *testing.T) {
	// The lowest-priority mapping is revoked; resolution must fall through to
	// the next eligible one even though it has a higher Priority number.
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	revoked := mkMapping("m-low-revoked", "GROUP_A", 1, []string{"ng-revoked"}, false, true)
	revoked.Revoked = true
	active := mkMapping("m-active", "GROUP_B", 50, []string{"ng-active"}, false, true)

	r, err := ResolveMapping(auth, []*types.EntraDeviceAuthMapping{revoked, active}, []string{"GROUP_A", "GROUP_B"})
	require.Nil(t, err)
	assert.Equal(t, []string{"m-active"}, r.MatchedMappingIDs)
	assert.Equal(t, []string{"ng-active"}, r.AutoGroups)
}

func TestResolveMapping_WildcardMatches(t *testing.T) {
	auth := &types.EntraDeviceAuth{MappingResolution: types.MappingResolutionStrictPriority}
	mappings := []*types.EntraDeviceAuthMapping{
		mkMapping("m-wild", "", 10, []string{"base"}, false, true), // "" == wildcard
	}
	r, err := ResolveMapping(auth, mappings, []string{"SOMETHING_ELSE"})
	require.Nil(t, err)
	assert.Equal(t, []string{"base"}, r.AutoGroups)
}
