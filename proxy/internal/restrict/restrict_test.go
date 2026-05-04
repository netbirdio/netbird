package restrict

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/proxy/internal/geolocation"
)

type mockGeo struct {
	countries map[string]string
}

func (m *mockGeo) LookupAddr(addr netip.Addr) geolocation.Result {
	return geolocation.Result{CountryCode: m.countries[addr.String()]}
}

func (m *mockGeo) Available() bool { return true }

func newMockGeo(entries map[string]string) *mockGeo {
	return &mockGeo{countries: entries}
}

func TestFilter_Check_NilFilter(t *testing.T) {
	var f *Filter
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_Check_AllowedCIDR(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.1.2.3"), nil))
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil))
}

func TestFilter_Check_BlockedCIDR(t *testing.T) {
	f := ParseFilter(FilterConfig{BlockedCIDRs: []string{"10.0.0.0/8"}})

	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("10.1.2.3"), nil))
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("192.168.1.1"), nil))
}

func TestFilter_Check_AllowedAndBlockedCIDR(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}, BlockedCIDRs: []string{"10.1.0.0/16"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.2.3.4"), nil), "allowed by allowlist, not in blocklist")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("10.1.2.3"), nil), "allowed by allowlist but in blocklist")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil), "not in allowlist")
}

func TestFilter_Check_AllowedCountry(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "US",
		"2.2.2.2": "DE",
		"3.3.3.3": "CN",
	})
	f := ParseFilter(FilterConfig{AllowedCountries: []string{"US", "DE"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "US in allowlist")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("2.2.2.2"), geo), "DE in allowlist")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("3.3.3.3"), geo), "CN not in allowlist")
}

func TestFilter_Check_BlockedCountry(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "CN",
		"2.2.2.2": "RU",
		"3.3.3.3": "US",
	})
	f := ParseFilter(FilterConfig{BlockedCountries: []string{"CN", "RU"}})

	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "CN in blocklist")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("2.2.2.2"), geo), "RU in blocklist")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("3.3.3.3"), geo), "US not in blocklist")
}

func TestFilter_Check_AllowedAndBlockedCountry(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "US",
		"2.2.2.2": "DE",
		"3.3.3.3": "CN",
	})
	// Allow US and DE, but block DE explicitly.
	f := ParseFilter(FilterConfig{AllowedCountries: []string{"US", "DE"}, BlockedCountries: []string{"DE"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "US allowed and not blocked")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("2.2.2.2"), geo), "DE allowed but also blocked, block wins")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("3.3.3.3"), geo), "CN not in allowlist")
}

func TestFilter_Check_UnknownCountryWithAllowlist(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "US",
	})
	f := ParseFilter(FilterConfig{AllowedCountries: []string{"US"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "known US in allowlist")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("9.9.9.9"), geo), "unknown country denied when allowlist is active")
}

func TestFilter_Check_UnknownCountryWithBlocklistOnly(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "CN",
	})
	f := ParseFilter(FilterConfig{BlockedCountries: []string{"CN"}})

	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "known CN in blocklist")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("9.9.9.9"), geo), "unknown country allowed when only blocklist is active")
}

func TestFilter_Check_CountryWithoutGeo(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCountries: []string{"US"}})
	assert.Equal(t, DenyGeoUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), nil), "nil geo with country allowlist")
}

func TestFilter_Check_CountryBlocklistWithoutGeo(t *testing.T) {
	f := ParseFilter(FilterConfig{BlockedCountries: []string{"CN"}})
	assert.Equal(t, DenyGeoUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), nil), "nil geo with country blocklist")
}

func TestFilter_Check_GeoUnavailable(t *testing.T) {
	geo := &unavailableGeo{}

	f := ParseFilter(FilterConfig{AllowedCountries: []string{"US"}})
	assert.Equal(t, DenyGeoUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), geo), "unavailable geo with country allowlist")

	f2 := ParseFilter(FilterConfig{BlockedCountries: []string{"CN"}})
	assert.Equal(t, DenyGeoUnavailable, f2.Check(netip.MustParseAddr("1.2.3.4"), geo), "unavailable geo with country blocklist")
}

func TestFilter_Check_CIDROnlySkipsGeo(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})

	// CIDR-only filter should never touch geo, so nil geo is fine.
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.1.2.3"), nil))
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil))
}

func TestFilter_Check_CIDRAllowThenCountryBlock(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"10.1.2.3": "CN",
		"10.2.3.4": "US",
	})
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}, BlockedCountries: []string{"CN"}})

	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("10.1.2.3"), geo), "CIDR allowed but country blocked")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.2.3.4"), geo), "CIDR allowed and country not blocked")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), geo), "CIDR denied before country check")
}

func TestParseFilter_Empty(t *testing.T) {
	f := ParseFilter(FilterConfig{})
	assert.Nil(t, f)
}

func TestParseFilter_InvalidCIDR(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"invalid", "10.0.0.0/8"}})

	assert.NotNil(t, f)
	assert.Len(t, f.AllowedCIDRs, 1, "invalid CIDR should be skipped")
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), f.AllowedCIDRs[0])
}

func TestFilter_HasRestrictions(t *testing.T) {
	assert.False(t, (*Filter)(nil).HasRestrictions())
	assert.False(t, (&Filter{}).HasRestrictions())
	assert.True(t, ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}}).HasRestrictions())
	assert.True(t, ParseFilter(FilterConfig{AllowedCountries: []string{"US"}}).HasRestrictions())
}

func TestFilter_Check_IPv6CIDR(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"2001:db8::/32"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("2001:db8::1"), nil), "v6 addr in v6 allowlist")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("2001:db9::1"), nil), "v6 addr not in v6 allowlist")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("10.1.2.3"), nil), "v4 addr not in v6 allowlist")
}

func TestFilter_Check_IPv4MappedIPv6(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})

	// A v4-mapped-v6 address like ::ffff:10.1.2.3 must match a v4 CIDR.
	v4mapped := netip.MustParseAddr("::ffff:10.1.2.3")
	assert.True(t, v4mapped.Is4In6(), "precondition: address is v4-in-v6")
	assert.Equal(t, Allow, f.Check(v4mapped, nil), "v4-mapped-v6 must match v4 CIDR after Unmap")

	v4mappedOutside := netip.MustParseAddr("::ffff:192.168.1.1")
	assert.Equal(t, DenyCIDR, f.Check(v4mappedOutside, nil), "v4-mapped-v6 outside v4 CIDR")
}

func TestFilter_Check_MixedV4V6CIDRs(t *testing.T) {
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.1.2.3"), nil), "v4 in v4 CIDR")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("2001:db8::1"), nil), "v6 in v6 CIDR")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("::ffff:10.1.2.3"), nil), "v4-mapped matches v4 CIDR")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil), "v4 not in either CIDR")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("fe80::1"), nil), "v6 not in either CIDR")
}

func TestParseFilter_CanonicalizesNonMaskedCIDR(t *testing.T) {
	// 1.1.1.1/24 has host bits set; ParseFilter should canonicalize to 1.1.1.0/24.
	f := ParseFilter(FilterConfig{AllowedCIDRs: []string{"1.1.1.1/24"}})
	assert.Equal(t, netip.MustParsePrefix("1.1.1.0/24"), f.AllowedCIDRs[0])

	// Verify it still matches correctly.
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.1.1.100"), nil))
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("1.1.2.1"), nil))
}

func TestFilter_Check_CountryCodeCaseInsensitive(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "US",
		"2.2.2.2": "DE",
		"3.3.3.3": "CN",
	})

	tests := []struct {
		name             string
		allowedCountries []string
		blockedCountries []string
		addr             string
		want             Verdict
	}{
		{
			name:             "lowercase allowlist matches uppercase MaxMind code",
			allowedCountries: []string{"us", "de"},
			addr:             "1.1.1.1",
			want:             Allow,
		},
		{
			name:             "mixed-case allowlist matches",
			allowedCountries: []string{"Us", "dE"},
			addr:             "2.2.2.2",
			want:             Allow,
		},
		{
			name:             "lowercase allowlist rejects non-matching country",
			allowedCountries: []string{"us", "de"},
			addr:             "3.3.3.3",
			want:             DenyCountry,
		},
		{
			name:             "lowercase blocklist blocks matching country",
			blockedCountries: []string{"cn"},
			addr:             "3.3.3.3",
			want:             DenyCountry,
		},
		{
			name:             "mixed-case blocklist blocks matching country",
			blockedCountries: []string{"Cn"},
			addr:             "3.3.3.3",
			want:             DenyCountry,
		},
		{
			name:             "lowercase blocklist does not block non-matching country",
			blockedCountries: []string{"cn"},
			addr:             "1.1.1.1",
			want:             Allow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ParseFilter(FilterConfig{AllowedCountries: tc.allowedCountries, BlockedCountries: tc.blockedCountries})
			got := f.Check(netip.MustParseAddr(tc.addr), geo)
			assert.Equal(t, tc.want, got)
		})
	}
}

// unavailableGeo simulates a GeoResolver whose database is not loaded.
type unavailableGeo struct{}

func (u *unavailableGeo) LookupAddr(_ netip.Addr) geolocation.Result { return geolocation.Result{} }
func (u *unavailableGeo) Available() bool                            { return false }

// mockCrowdSec is a test implementation of CrowdSecChecker.
type mockCrowdSec struct {
	decisions map[string]*CrowdSecDecision
	ready     bool
}

func (m *mockCrowdSec) CheckIP(addr netip.Addr) *CrowdSecDecision {
	return m.decisions[addr.Unmap().String()]
}

func (m *mockCrowdSec) Ready() bool { return m.ready }

func TestFilter_CrowdSec_Enforce_Ban(t *testing.T) {
	cs := &mockCrowdSec{
		decisions: map[string]*CrowdSecDecision{"1.2.3.4": {Type: DecisionBan}},
		ready:     true,
	}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecEnforce})

	assert.Equal(t, DenyCrowdSecBan, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("5.6.7.8"), nil))
}

func TestFilter_CrowdSec_Enforce_Captcha(t *testing.T) {
	cs := &mockCrowdSec{
		decisions: map[string]*CrowdSecDecision{"1.2.3.4": {Type: DecisionCaptcha}},
		ready:     true,
	}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecEnforce})

	assert.Equal(t, DenyCrowdSecCaptcha, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_CrowdSec_Enforce_Throttle(t *testing.T) {
	cs := &mockCrowdSec{
		decisions: map[string]*CrowdSecDecision{"1.2.3.4": {Type: DecisionThrottle}},
		ready:     true,
	}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecEnforce})

	assert.Equal(t, DenyCrowdSecThrottle, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_CrowdSec_Observe_DoesNotBlock(t *testing.T) {
	cs := &mockCrowdSec{
		decisions: map[string]*CrowdSecDecision{"1.2.3.4": {Type: DecisionBan}},
		ready:     true,
	}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecObserve})

	verdict := f.Check(netip.MustParseAddr("1.2.3.4"), nil)
	assert.Equal(t, DenyCrowdSecBan, verdict, "verdict should be ban")
	assert.True(t, f.IsObserveOnly(verdict), "should be observe-only")
}

func TestFilter_CrowdSec_Enforce_NotReady(t *testing.T) {
	cs := &mockCrowdSec{ready: false}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecEnforce})

	assert.Equal(t, DenyCrowdSecUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_CrowdSec_Observe_NotReady_Allows(t *testing.T) {
	cs := &mockCrowdSec{ready: false}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecObserve})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_CrowdSec_Off(t *testing.T) {
	cs := &mockCrowdSec{
		decisions: map[string]*CrowdSecDecision{"1.2.3.4": {Type: DecisionBan}},
		ready:     true,
	}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecOff})

	// CrowdSecOff means the filter is nil (no restrictions).
	assert.Nil(t, f)
}

func TestFilter_IsObserveOnly(t *testing.T) {
	f := &Filter{CrowdSecMode: CrowdSecObserve}
	assert.True(t, f.IsObserveOnly(DenyCrowdSecBan))
	assert.True(t, f.IsObserveOnly(DenyCrowdSecCaptcha))
	assert.True(t, f.IsObserveOnly(DenyCrowdSecThrottle))
	assert.True(t, f.IsObserveOnly(DenyCrowdSecUnavailable))
	assert.False(t, f.IsObserveOnly(DenyCIDR))
	assert.False(t, f.IsObserveOnly(Allow))

	f2 := &Filter{CrowdSecMode: CrowdSecEnforce}
	assert.False(t, f2.IsObserveOnly(DenyCrowdSecBan))
}

// TestFilter_LayerInteraction exercises the evaluation order across all three
// restriction layers: CIDR -> Country -> CrowdSec. Each layer can only further
// restrict; no layer can relax a denial from an earlier layer.
//
//	Layer order    | Behavior
//	---------------|-------------------------------------------------------
//	1. CIDR        | Allowlist narrows to specific ranges, blocklist removes
//	               | specific ranges. Deny here → stop, CrowdSec never runs.
//	2. Country     | Allowlist/blocklist by geo. Deny here → stop.
//	3. CrowdSec    | IP reputation. Can block IPs that passed layers 1-2.
//	               | Observe mode: verdict returned but caller doesn't block.
func TestFilter_LayerInteraction(t *testing.T) {
	bannedIP := "10.1.2.3"
	cleanIP := "10.2.3.4"
	outsideIP := "192.168.1.1"

	cs := &mockCrowdSec{
		decisions: map[string]*CrowdSecDecision{bannedIP: {Type: DecisionBan}},
		ready:     true,
	}
	geo := newMockGeo(map[string]string{
		bannedIP:  "US",
		cleanIP:   "US",
		outsideIP: "CN",
	})

	tests := []struct {
		name   string
		config FilterConfig
		addr   string
		want   Verdict
	}{
		// CIDR allowlist + CrowdSec enforce: CrowdSec blocks inside allowed range
		{
			name:   "allowed CIDR + CrowdSec banned",
			config: FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   bannedIP,
			want:   DenyCrowdSecBan,
		},
		{
			name:   "allowed CIDR + CrowdSec clean",
			config: FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   cleanIP,
			want:   Allow,
		},
		{
			name:   "CIDR deny stops before CrowdSec",
			config: FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   outsideIP,
			want:   DenyCIDR,
		},

		// CIDR blocklist + CrowdSec enforce: blocklist blocks first, CrowdSec blocks remaining
		{
			name:   "blocked CIDR stops before CrowdSec",
			config: FilterConfig{BlockedCIDRs: []string{"10.1.0.0/16"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   bannedIP,
			want:   DenyCIDR,
		},
		{
			name:   "not in blocklist + CrowdSec clean",
			config: FilterConfig{BlockedCIDRs: []string{"10.1.0.0/16"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   cleanIP,
			want:   Allow,
		},

		// Country allowlist + CrowdSec enforce
		{
			name:   "allowed country + CrowdSec banned",
			config: FilterConfig{AllowedCountries: []string{"US"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   bannedIP,
			want:   DenyCrowdSecBan,
		},
		{
			name:   "country deny stops before CrowdSec",
			config: FilterConfig{AllowedCountries: []string{"US"}, CrowdSec: cs, CrowdSecMode: CrowdSecEnforce},
			addr:   outsideIP,
			want:   DenyCountry,
		},

		// All three layers: CIDR allowlist + country blocklist + CrowdSec
		{
			name: "all layers: CIDR allow + country allow + CrowdSec ban",
			config: FilterConfig{
				AllowedCIDRs:     []string{"10.0.0.0/8"},
				BlockedCountries: []string{"CN"},
				CrowdSec:         cs,
				CrowdSecMode:     CrowdSecEnforce,
			},
			addr: bannedIP, // 10.x (CIDR ok), US (country ok), banned (CrowdSec deny)
			want: DenyCrowdSecBan,
		},
		{
			name: "all layers: CIDR deny short-circuits everything",
			config: FilterConfig{
				AllowedCIDRs:     []string{"10.0.0.0/8"},
				BlockedCountries: []string{"CN"},
				CrowdSec:         cs,
				CrowdSecMode:     CrowdSecEnforce,
			},
			addr: outsideIP, // 192.x (CIDR deny)
			want: DenyCIDR,
		},

		// Observe mode: verdict returned but IsObserveOnly is true
		{
			name:   "observe mode: CrowdSec banned inside allowed CIDR",
			config: FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}, CrowdSec: cs, CrowdSecMode: CrowdSecObserve},
			addr:   bannedIP,
			want:   DenyCrowdSecBan, // verdict is ban, caller checks IsObserveOnly
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ParseFilter(tc.config)
			got := f.Check(netip.MustParseAddr(tc.addr), geo)
			assert.Equal(t, tc.want, got)

			// Verify observe mode flag when applicable.
			if tc.config.CrowdSecMode == CrowdSecObserve && got.IsCrowdSec() {
				assert.True(t, f.IsObserveOnly(got), "observe mode verdict should be observe-only")
			}
			if tc.config.CrowdSecMode == CrowdSecEnforce && got.IsCrowdSec() {
				assert.False(t, f.IsObserveOnly(got), "enforce mode verdict should not be observe-only")
			}
		})
	}
}

func TestFilter_CrowdSec_Enforce_NilChecker(t *testing.T) {
	// LAPI not configured: checker is nil but mode is enforce. Must fail closed.
	f := ParseFilter(FilterConfig{CrowdSec: nil, CrowdSecMode: CrowdSecEnforce})

	assert.Equal(t, DenyCrowdSecUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_CrowdSec_Observe_NilChecker(t *testing.T) {
	// LAPI not configured: checker is nil but mode is observe. Must allow.
	f := ParseFilter(FilterConfig{CrowdSec: nil, CrowdSecMode: CrowdSecObserve})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.2.3.4"), nil))
}

func TestFilter_HasRestrictions_CrowdSec(t *testing.T) {
	cs := &mockCrowdSec{ready: true}
	f := ParseFilter(FilterConfig{CrowdSec: cs, CrowdSecMode: CrowdSecEnforce})
	assert.True(t, f.HasRestrictions())

	// Enforce mode without checker (LAPI not configured): still has restrictions
	// because Check() will fail-closed with DenyCrowdSecUnavailable.
	f2 := ParseFilter(FilterConfig{CrowdSec: nil, CrowdSecMode: CrowdSecEnforce})
	assert.True(t, f2.HasRestrictions())
}
