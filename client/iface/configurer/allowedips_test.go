package configurer

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPeer = "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"

func TestAllowedIPStoreUnknownPeer(t *testing.T) {
	s := newAllowedIPStore()

	prefixes, ok := s.get(testPeer)
	assert.False(t, ok, "an unconfigured peer must be reported as unknown, not as one without prefixes")
	assert.Nil(t, prefixes, "an unknown peer has no prefixes")
}

func TestAllowedIPStoreAddUnions(t *testing.T) {
	s := newAllowedIPStore()
	overlay := netip.MustParsePrefix("100.64.0.1/32")
	routed := netip.MustParsePrefix("10.20.0.0/16")

	s.set(testPeer, []netip.Prefix{overlay})
	// A peer update does not replace allowed IPs, and a repeated prefix must not be doubled.
	s.add(testPeer, []netip.Prefix{overlay, routed})

	prefixes, ok := s.get(testPeer)
	require.True(t, ok, "peer must be known after set")
	assert.Equal(t, []netip.Prefix{overlay, routed}, prefixes, "add must union rather than replace")
}

func TestAllowedIPStoreGetReturnsCopy(t *testing.T) {
	s := newAllowedIPStore()
	overlay := netip.MustParsePrefix("100.64.0.1/32")
	s.set(testPeer, []netip.Prefix{overlay})

	prefixes, ok := s.get(testPeer)
	require.True(t, ok, "peer must be known after set")
	prefixes[0] = netip.MustParsePrefix("0.0.0.0/0")

	stored, _ := s.get(testPeer)
	assert.Equal(t, []netip.Prefix{overlay}, stored, "a caller mutating the returned slice must not corrupt the store")
}

func TestAllowedIPStoreForgetAndReset(t *testing.T) {
	s := newAllowedIPStore()
	s.set(testPeer, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")})
	s.set("other", []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")})

	s.forget(testPeer)
	_, ok := s.get(testPeer)
	assert.False(t, ok, "a forgotten peer must be unknown")
	_, ok = s.get("other")
	assert.True(t, ok, "forgetting one peer must not touch the others")

	s.reset()
	_, ok = s.get("other")
	assert.False(t, ok, "reset must drop every peer")
}

func TestIPNetsToPrefixes(t *testing.T) {
	tests := []struct {
		name  string
		ipNet net.IPNet
		want  string
	}{
		{
			name:  "v4",
			ipNet: net.IPNet{IP: net.IP{10, 20, 0, 0}, Mask: net.CIDRMask(16, 32)},
			want:  "10.20.0.0/16",
		},
		{
			name:  "v4 mapped under a 128 bit mask",
			ipNet: net.IPNet{IP: net.ParseIP("10.20.0.0"), Mask: net.CIDRMask(112, 128)},
			want:  "10.20.0.0/16",
		},
		{
			name:  "v6",
			ipNet: net.IPNet{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(64, 128)},
			want:  "fd00::/64",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ipNetsToPrefixes([]net.IPNet{tc.ipNet})
			require.Len(t, got, 1, "the address must be converted, not dropped")
			assert.Equal(t, tc.want, got[0].String(), "converted prefix")
		})
	}
}

func TestIPNetsToPrefixesRoundTrip(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/32"),
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("fd00::/64"),
	}

	assert.Equal(t, prefixes, ipNetsToPrefixes(prefixesToIPNets(prefixes)),
		"prefixes handed to a device must come back unchanged")
}

func TestAllowedIPStoreNormalizesMappedPrefixes(t *testing.T) {
	s := newAllowedIPStore()
	v4 := netip.MustParsePrefix("10.20.0.0/16")
	mapped := netip.PrefixFrom(netip.AddrFrom16(v4.Addr().As16()), 112)

	s.set(testPeer, []netip.Prefix{mapped})
	// A v4 rule only matches a v4-mapped address once it has been unmapped, so the store must
	// hold the plain form and recognise the two spellings as the same prefix.
	s.add(testPeer, []netip.Prefix{v4})

	prefixes, ok := s.get(testPeer)
	require.True(t, ok, "peer must be known after set")
	assert.Equal(t, []netip.Prefix{v4}, prefixes, "a mapped prefix must be stored unmapped and not duplicated")
}

func TestNormalizePrefix(t *testing.T) {
	v4 := netip.MustParsePrefix("10.20.0.0/16")
	v6 := netip.MustParsePrefix("fd00::/64")

	assert.Equal(t, v4, normalizePrefix(v4), "a plain v4 prefix is unchanged")
	assert.Equal(t, v6, normalizePrefix(v6), "a real v6 prefix is unchanged")
	assert.Equal(t, v4, normalizePrefix(netip.PrefixFrom(netip.AddrFrom16(v4.Addr().As16()), 112)),
		"a mapped prefix under a 128 bit mask becomes plain v4")
	assert.Equal(t, v4, normalizePrefix(netip.PrefixFrom(netip.AddrFrom16(v4.Addr().As16()), 16)),
		"a mapped prefix already carrying v4 bits keeps them")
}

func TestAllowedIPStoreAddExistingDoesNotCreate(t *testing.T) {
	s := newAllowedIPStore()
	routed := netip.MustParsePrefix("10.20.0.0/16")

	// An update-only device operation on an absent peer is a silent no-op, so nothing may be
	// recorded for a peer the store does not already know.
	s.addExisting(testPeer, []netip.Prefix{routed})
	_, ok := s.get(testPeer)
	assert.False(t, ok, "addExisting must not record an unknown peer")

	overlay := netip.MustParsePrefix("100.64.0.1/32")
	s.set(testPeer, []netip.Prefix{overlay})
	s.addExisting(testPeer, []netip.Prefix{routed})

	prefixes, _ := s.get(testPeer)
	assert.Equal(t, []netip.Prefix{overlay, routed}, prefixes, "addExisting must union onto a known peer")
}
