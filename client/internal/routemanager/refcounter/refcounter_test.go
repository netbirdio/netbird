package refcounter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeysMatching verifies KeysMatching returns exactly the keys whose stored Out satisfies the
// predicate — the primitive ReconcilePeerAllowedIPs relies on to enumerate a single peer's routed
// prefixes without touching the others.
func TestKeysMatching(t *testing.T) {
	rc := New[netip.Prefix, string, string](
		func(_ netip.Prefix, peerKey string) (string, error) { return peerKey, nil },
		func(netip.Prefix, string) error { return nil },
	)

	peerA1 := netip.MustParsePrefix("10.0.0.0/24")
	peerA2 := netip.MustParsePrefix("10.1.0.0/24")
	peerB1 := netip.MustParsePrefix("10.2.0.0/24")

	_, err := rc.Increment(peerA1, "peerA")
	require.NoError(t, err)
	_, err = rc.Increment(peerA2, "peerA")
	require.NoError(t, err)
	_, err = rc.Increment(peerB1, "peerB")
	require.NoError(t, err)

	// a second reference to peerA1 must not duplicate it in the result
	_, err = rc.Increment(peerA1, "peerA")
	require.NoError(t, err)

	keysA := rc.KeysMatching(func(out string) bool { return out == "peerA" })
	assert.ElementsMatch(t, []netip.Prefix{peerA1, peerA2}, keysA)

	keysB := rc.KeysMatching(func(out string) bool { return out == "peerB" })
	assert.ElementsMatch(t, []netip.Prefix{peerB1}, keysB)

	keysNone := rc.KeysMatching(func(out string) bool { return out == "missing" })
	assert.Empty(t, keysNone)
}
