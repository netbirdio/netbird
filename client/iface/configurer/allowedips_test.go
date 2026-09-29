package configurer

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The store keys on the parsed key, so the tests use two distinct ones rather than names.
var (
	testPeer  = wgtypes.Key{1}
	otherPeer = wgtypes.Key{2}
)

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
	s.set(otherPeer, []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")})

	s.forget(testPeer)
	_, ok := s.get(testPeer)
	assert.False(t, ok, "a forgotten peer must be unknown")
	_, ok = s.get(otherPeer)
	assert.True(t, ok, "forgetting one peer must not touch the others")

	s.reset()
	_, ok = s.get(otherPeer)
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
	// A prefix shorter than /96 inside the mapped range is a genuine v6 prefix. Unmapping it
	// would pair a v4 address with a v6 sized mask, which is invalid, and the store would then
	// record a zero prefix that can never recreate the allowed IP.
	for _, tc := range []string{"::ffff:0:0/64", "::ffff:1.2.3.4/80", "::ffff:1.2.3.4/95"} {
		got := normalizePrefix(netip.MustParsePrefix(tc))
		assert.True(t, got.IsValid(), "%s must normalize to a valid prefix", tc)
		assert.False(t, got.Addr().Is4(), "%s must stay v6", tc)
	}
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

func TestAllowedIPStoreHandsPrefixOverToTheNewOwner(t *testing.T) {
	s := newAllowedIPStore()
	routed := netip.MustParsePrefix("10.20.0.0/16")
	other := otherPeer

	s.set(testPeer, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), routed})
	s.set(other, []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")})

	// The device takes an allowed IP away from its previous holder when it is configured on
	// another peer, so the store must do the same rather than list it under both.
	s.addExisting(other, []netip.Prefix{routed})

	previous, _ := s.get(testPeer)
	assert.NotContains(t, previous, routed, "the previous owner must lose the prefix")
	current, _ := s.get(other)
	assert.Contains(t, current, routed, "the new owner must hold the prefix")
}

func TestAllowedIPStoreForgetReleasesOwnership(t *testing.T) {
	s := newAllowedIPStore()
	routed := netip.MustParsePrefix("10.20.0.0/16")

	s.set(testPeer, []netip.Prefix{routed})
	s.forget(testPeer)
	s.set(otherPeer, []netip.Prefix{routed})

	// A forgotten peer must not be resurrected as a key in the peer map by a later claim.
	_, ok := s.get(testPeer)
	assert.False(t, ok, "the forgotten peer must stay unknown")
	current, _ := s.get(otherPeer)
	assert.Equal(t, []netip.Prefix{routed}, current, "the new owner must hold the prefix")
}

func TestNormalizePrefixClearsHostBits(t *testing.T) {
	// A device stores a prefix masked, so a caller passing host bits must still match what a
	// device fallback seeded, otherwise that prefix could never be removed by value.
	assert.Equal(t, netip.MustParsePrefix("10.20.0.0/16"),
		normalizePrefix(netip.MustParsePrefix("10.20.0.1/16")), "host bits must be cleared")
	assert.Equal(t, netip.MustParsePrefix("fd00::/64"),
		normalizePrefix(netip.MustParsePrefix("fd00::1/64")), "host bits must be cleared for v6")
}

func TestIPNetsToPrefixesKeepsV6InTheMappedRange(t *testing.T) {
	// ::ffff:0:0/64 reads as v4-mapped but is a genuine v6 prefix: unmapping it would leave a
	// v4 address under a 64 bit mask, which is invalid, and the allowed IP would be dropped.
	got := ipNetsToPrefixes([]net.IPNet{{
		IP:   net.ParseIP("::ffff:0:0"),
		Mask: net.CIDRMask(64, 128),
	}})

	require.Len(t, got, 1, "the prefix must be converted, not dropped")
	assert.False(t, got[0].Addr().Is4(), "a v6 prefix in the mapped range must not become v4")
	assert.Equal(t, 64, got[0].Bits(), "the prefix length must survive the conversion")
}

func TestPrefixesToIPNetsNormalizes(t *testing.T) {
	// net.IPNet prints a v4-mapped address as v4 but takes the length from its 16 byte
	// mask, so an unnormalized ::ffff:10.1.2.3/64 reaches a userspace device as 10.1.2.3/0,
	// an allowed IP that matches every v4 address.
	tests := []struct {
		name  string
		given string
		want  string
	}{
		{name: "mapped below /96", given: "::ffff:10.1.2.3/64", want: "::/64"},
		{name: "mapped at /112", given: "::ffff:10.1.2.3/112", want: "10.1.0.0/16"},
		{name: "host bits are cleared", given: "10.20.0.1/16", want: "10.20.0.0/16"},
		{name: "v6 is untouched", given: "fd00::1/64", want: "fd00::/64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := prefixesToIPNets([]netip.Prefix{netip.MustParsePrefix(tc.given)})
			require.Len(t, got, 1, "the prefix must be converted, not dropped")
			assert.Equal(t, tc.want, got[0].String(), "what the device is given")
			assert.NotEqual(t, 0, mustOnes(t, got[0]), "a device must never be given a zero length allowed IP")
		})
	}
}

func mustOnes(t *testing.T, ipNet net.IPNet) int {
	t.Helper()

	ones, _ := ipNet.Mask.Size()
	return ones
}

// TestPrefixesToIPNetsAgreesWithTheStore pins the property the store depends on: what a
// device is given and what is recorded for it are the same prefix.
func TestPrefixesToIPNetsAgreesWithTheStore(t *testing.T) {
	for _, given := range []string{"::ffff:10.1.2.3/64", "::ffff:10.1.2.3/112", "10.20.0.1/16", "fd00::1/64"} {
		prefix := netip.MustParsePrefix(given)

		toDevice := prefixesToIPNets([]netip.Prefix{prefix})
		recorded := normalizePrefix(prefix)

		assert.Equal(t, recorded.String(), toDevice[0].String(),
			"%s must reach the device in the form the store records", given)
	}
}
