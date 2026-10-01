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
