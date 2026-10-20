package refcounter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReapplyMatching verifies ReapplyMatching invokes apply for exactly the keys whose stored
// Out satisfies the predicate (no duplicates for multiply-referenced keys) — the primitive
// ReconcilePeerAllowedIPs relies on to re-apply a single peer's routed prefixes.
func TestReapplyMatching(t *testing.T) {
	rc := New[netip.Prefix, string, string](
		func(_ netip.Prefix, peerKey string) (string, error) { return peerKey, nil },
		func(netip.Prefix, string) error { return nil },
	)

	peerA1 := netip.MustParsePrefix("10.0.0.0/24")
	peerA2 := netip.MustParsePrefix("10.1.0.0/24")
	peerB1 := netip.MustParsePrefix("10.2.0.0/24")

	for prefix, peer := range map[netip.Prefix]string{peerA1: "peerA", peerA2: "peerA", peerB1: "peerB"} {
		_, err := rc.Increment(prefix, peer)
		require.NoError(t, err)
	}
	// a second reference must not make the key applied twice
	_, err := rc.Increment(peerA1, "peerA")
	require.NoError(t, err)

	var applied []netip.Prefix
	err = rc.ReapplyMatching(
		func(out string) bool { return out == "peerA" },
		func(key netip.Prefix) error { applied = append(applied, key); return nil },
	)
	require.NoError(t, err)
	assert.ElementsMatch(t, []netip.Prefix{peerA1, peerA2}, applied)

	var none []netip.Prefix
	err = rc.ReapplyMatching(
		func(out string) bool { return out == "missing" },
		func(key netip.Prefix) error { none = append(none, key); return nil },
	)
	require.NoError(t, err)
	assert.Empty(t, none)
}
