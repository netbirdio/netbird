package certposture

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveWindow(t *testing.T) {
	// An end-to-end run shortens the window so a renewal can be watched in seconds
	// rather than half a day. Anything it cannot make sense of leaves the default in
	// place, because a window nobody intended is a security property nobody chose.
	tests := []struct {
		name string
		env  string
		want time.Duration
	}{
		{name: "unset keeps the default", env: "", want: Window},
		{name: "a test-sized window is taken", env: "30s", want: 30 * time.Second},
		{name: "garbage keeps the default", env: "soon", want: Window},
		{name: "below the floor keeps the default", env: "10ms", want: Window},
		{name: "above the ceiling keeps the default", env: "100h", want: Window},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvWindow, tt.env)
			if tt.env == "" {
				require.NoError(t, os.Unsetenv(EnvWindow))
			}
			assert.Equal(t, tt.want, resolveWindow())
		})
	}
}

func TestChallenger_HonoursAShortenedWindow(t *testing.T) {
	// The window is what a nonce is stamped with, so a shortened one has to make a
	// nonce expire sooner, not just change a number in a log line.
	short := 2 * time.Second
	c := &Challenger{secret: []byte("secret"), window: short}
	peerKey := []byte("peer-key")

	issued := time.Unix(1_790_000_000, 0)
	nonce := c.Nonce(peerKey, issued)

	require.NoError(t, c.verifyNonce(nonce, peerKey, issued), "a nonce is valid when issued")
	require.NoError(t, c.verifyNonce(nonce, peerKey, issued.Add(short)), "and through the window after it")
	assert.ErrorIs(t, c.verifyNonce(nonce, peerKey, issued.Add(3*short)), ErrNonceExpired,
		"a shortened window must actually expire the nonce sooner")
}

// heldNonceAlwaysAccepted walks ten windows and, at every step, checks the nonce the peer
// would be holding if it were re-stamped every period starting at offset. It returns how
// many of those checks would have rejected the peer.
func heldNonceAlwaysAccepted(c *Challenger, peerKey []byte, period, offset time.Duration) int {
	start := time.Unix(0, 0).UTC().Add(offset)
	var rejected int
	for elapsed := time.Duration(0); elapsed < 10*Window; elapsed += 7 * time.Minute {
		lastRefresh := start.Add(elapsed / period * period)
		if c.verifyNonce(c.Nonce(peerKey, lastRefresh), peerKey, start.Add(elapsed)) != nil {
			rejected++
		}
	}
	return rejected
}

// TestNonce_StaysValidWhenRestampedWithinAWindow is the reason management keeps no per-peer
// nonce state. A nonce carries the window it was minted in, not the instant, and is accepted
// for that window and the next. A peer re-stamped at least once per window therefore can
// never be holding one that has fallen outside the accepted pair, whoever it is and whenever
// it was last served. There is nothing to track and nothing to search for: the guarantee
// comes from the cadence alone.
//
// The offsets matter: each account is given a phase of its own so a restart does not fan out
// to every account at once, so the property has to hold off the window boundary too.
func TestNonce_StaysValidWhenRestampedWithinAWindow(t *testing.T) {
	c := &Challenger{secret: []byte("secret"), window: Window}
	peerKey := []byte("peer-key")

	for _, period := range []time.Duration{Window / 3, Window / 2, Window} {
		for _, offset := range []time.Duration{0, Window / 7, Window / 2, Window - time.Minute} {
			t.Run(period.String()+"+"+offset.String(), func(t *testing.T) {
				assert.Zero(t, heldNonceAlwaysAccepted(c, peerKey, period, offset),
					"a peer re-stamped every %v is never left holding an expired nonce", period)
			})
		}
	}
}

func TestNonce_ExpiresWhenRestampedTooSlowly(t *testing.T) {
	// The counterpart, which is what gives the test above its teeth. Note the aligned case
	// does not fail: a cadence of exactly two windows that lands on the boundaries is
	// covered by the grace window. Off the boundary it is not, and real refreshes are off
	// the boundary by design.
	c := &Challenger{secret: []byte("secret"), window: Window}
	peerKey := []byte("peer-key")

	assert.Zero(t, heldNonceAlwaysAccepted(c, peerKey, 2*Window, 0),
		"two windows exactly on the boundary happens to be covered by the grace window")
	assert.NotZero(t, heldNonceAlwaysAccepted(c, peerKey, 2*Window, Window/2),
		"the same cadence off the boundary must leave the peer rejected for a stretch")
}
