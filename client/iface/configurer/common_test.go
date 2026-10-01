package configurer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
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
