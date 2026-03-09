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
	f := ParseFilter([]string{"10.0.0.0/8"}, nil, nil, nil)

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.1.2.3"), nil))
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil))
}

func TestFilter_Check_BlockedCIDR(t *testing.T) {
	f := ParseFilter(nil, []string{"10.0.0.0/8"}, nil, nil)

	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("10.1.2.3"), nil))
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("192.168.1.1"), nil))
}

func TestFilter_Check_AllowedAndBlockedCIDR(t *testing.T) {
	f := ParseFilter([]string{"10.0.0.0/8"}, []string{"10.1.0.0/16"}, nil, nil)

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
	f := ParseFilter(nil, nil, []string{"US", "DE"}, nil)

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
	f := ParseFilter(nil, nil, nil, []string{"CN", "RU"})

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
	f := ParseFilter(nil, nil, []string{"US", "DE"}, []string{"DE"})

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "US allowed and not blocked")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("2.2.2.2"), geo), "DE allowed but also blocked, block wins")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("3.3.3.3"), geo), "CN not in allowlist")
}

func TestFilter_Check_UnknownCountryWithAllowlist(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "US",
	})
	f := ParseFilter(nil, nil, []string{"US"}, nil)

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "known US in allowlist")
	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("9.9.9.9"), geo), "unknown country denied when allowlist is active")
}

func TestFilter_Check_UnknownCountryWithBlocklistOnly(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"1.1.1.1": "CN",
	})
	f := ParseFilter(nil, nil, nil, []string{"CN"})

	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("1.1.1.1"), geo), "known CN in blocklist")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("9.9.9.9"), geo), "unknown country allowed when only blocklist is active")
}

func TestFilter_Check_CountryWithoutGeo(t *testing.T) {
	f := ParseFilter(nil, nil, []string{"US"}, nil)
	assert.Equal(t, DenyGeoUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), nil), "nil geo with country allowlist")
}

func TestFilter_Check_CountryBlocklistWithoutGeo(t *testing.T) {
	f := ParseFilter(nil, nil, nil, []string{"CN"})
	assert.Equal(t, DenyGeoUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), nil), "nil geo with country blocklist")
}

func TestFilter_Check_GeoUnavailable(t *testing.T) {
	geo := &unavailableGeo{}

	f := ParseFilter(nil, nil, []string{"US"}, nil)
	assert.Equal(t, DenyGeoUnavailable, f.Check(netip.MustParseAddr("1.2.3.4"), geo), "unavailable geo with country allowlist")

	f2 := ParseFilter(nil, nil, nil, []string{"CN"})
	assert.Equal(t, DenyGeoUnavailable, f2.Check(netip.MustParseAddr("1.2.3.4"), geo), "unavailable geo with country blocklist")
}

func TestFilter_Check_CIDROnlySkipsGeo(t *testing.T) {
	f := ParseFilter([]string{"10.0.0.0/8"}, nil, nil, nil)

	// CIDR-only filter should never touch geo, so nil geo is fine.
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.1.2.3"), nil))
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil))
}

func TestFilter_Check_CIDRAllowThenCountryBlock(t *testing.T) {
	geo := newMockGeo(map[string]string{
		"10.1.2.3": "CN",
		"10.2.3.4": "US",
	})
	f := ParseFilter([]string{"10.0.0.0/8"}, nil, nil, []string{"CN"})

	assert.Equal(t, DenyCountry, f.Check(netip.MustParseAddr("10.1.2.3"), geo), "CIDR allowed but country blocked")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.2.3.4"), geo), "CIDR allowed and country not blocked")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), geo), "CIDR denied before country check")
}

func TestParseFilter_Empty(t *testing.T) {
	f := ParseFilter(nil, nil, nil, nil)
	assert.Nil(t, f)
}

func TestParseFilter_InvalidCIDR(t *testing.T) {
	f := ParseFilter([]string{"invalid", "10.0.0.0/8"}, nil, nil, nil)

	assert.NotNil(t, f)
	assert.Len(t, f.AllowedCIDRs, 1, "invalid CIDR should be skipped")
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), f.AllowedCIDRs[0])
}

func TestFilter_HasRestrictions(t *testing.T) {
	assert.False(t, (*Filter)(nil).HasRestrictions())
	assert.False(t, (&Filter{}).HasRestrictions())
	assert.True(t, ParseFilter([]string{"10.0.0.0/8"}, nil, nil, nil).HasRestrictions())
	assert.True(t, ParseFilter(nil, nil, []string{"US"}, nil).HasRestrictions())
}

func TestFilter_Check_IPv6CIDR(t *testing.T) {
	f := ParseFilter([]string{"2001:db8::/32"}, nil, nil, nil)

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("2001:db8::1"), nil), "v6 addr in v6 allowlist")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("2001:db9::1"), nil), "v6 addr not in v6 allowlist")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("10.1.2.3"), nil), "v4 addr not in v6 allowlist")
}

func TestFilter_Check_IPv4MappedIPv6(t *testing.T) {
	f := ParseFilter([]string{"10.0.0.0/8"}, nil, nil, nil)

	// A v4-mapped-v6 address like ::ffff:10.1.2.3 must match a v4 CIDR.
	v4mapped := netip.MustParseAddr("::ffff:10.1.2.3")
	assert.True(t, v4mapped.Is4In6(), "precondition: address is v4-in-v6")
	assert.Equal(t, Allow, f.Check(v4mapped, nil), "v4-mapped-v6 must match v4 CIDR after Unmap")

	v4mappedOutside := netip.MustParseAddr("::ffff:192.168.1.1")
	assert.Equal(t, DenyCIDR, f.Check(v4mappedOutside, nil), "v4-mapped-v6 outside v4 CIDR")
}

func TestFilter_Check_MixedV4V6CIDRs(t *testing.T) {
	f := ParseFilter([]string{"10.0.0.0/8", "2001:db8::/32"}, nil, nil, nil)

	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("10.1.2.3"), nil), "v4 in v4 CIDR")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("2001:db8::1"), nil), "v6 in v6 CIDR")
	assert.Equal(t, Allow, f.Check(netip.MustParseAddr("::ffff:10.1.2.3"), nil), "v4-mapped matches v4 CIDR")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("192.168.1.1"), nil), "v4 not in either CIDR")
	assert.Equal(t, DenyCIDR, f.Check(netip.MustParseAddr("fe80::1"), nil), "v6 not in either CIDR")
}

func TestParseFilter_CanonicalizesNonMaskedCIDR(t *testing.T) {
	// 1.1.1.1/24 has host bits set; ParseFilter should canonicalize to 1.1.1.0/24.
	f := ParseFilter([]string{"1.1.1.1/24"}, nil, nil, nil)
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
			f := ParseFilter(nil, nil, tc.allowedCountries, tc.blockedCountries)
			got := f.Check(netip.MustParseAddr(tc.addr), geo)
			assert.Equal(t, tc.want, got)
		})
	}
}

// unavailableGeo simulates a GeoResolver whose database is not loaded.
type unavailableGeo struct{}

func (u *unavailableGeo) LookupAddr(_ netip.Addr) geolocation.Result { return geolocation.Result{} }
func (u *unavailableGeo) Available() bool                             { return false }
