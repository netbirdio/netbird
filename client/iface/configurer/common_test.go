package configurer

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestNormalizePrefixClearsHostBits(t *testing.T) {
	// A device stores a prefix masked, so a caller passing host bits must still match what a
	// device fallback seeded, otherwise that prefix could never be removed by value.
	assert.Equal(t, netip.MustParsePrefix("10.20.0.0/16"),
		normalizePrefix(netip.MustParsePrefix("10.20.0.1/16")), "host bits must be cleared")
	assert.Equal(t, netip.MustParsePrefix("fd00::/64"),
		normalizePrefix(netip.MustParsePrefix("fd00::1/64")), "host bits must be cleared for v6")
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

func TestPrefixesToIPNetsAgreesWithTheStore(t *testing.T) {
	for _, given := range []string{"::ffff:10.1.2.3/64", "::ffff:10.1.2.3/112", "10.20.0.1/16", "fd00::1/64"} {
		prefix := netip.MustParsePrefix(given)

		toDevice := prefixesToIPNets([]netip.Prefix{prefix})
		recorded := normalizePrefix(prefix)

		assert.Equal(t, recorded.String(), toDevice[0].String(),
			"%s must reach the device in the form the store records", given)
	}
}

func mustOnes(t *testing.T, ipNet net.IPNet) int {
	t.Helper()

	ones, _ := ipNet.Mask.Size()
	return ones
}
