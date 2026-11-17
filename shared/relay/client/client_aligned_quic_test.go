//go:build devcert

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The aligned heartbeat rides on the auth message, not on the transport, so it
// works over QUIC the same way. The devcert build serves QUIC without a
// certificate and lets the client skip verification.
func TestAlignedClientWithStockPeerOverQUIC(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeQUIC))
	alice := runAlignedWithStockPeer(t, "127.0.0.1:50912")
	assert.Equal(t, "quic", alice.Transport(), "transport")
}

// An old relay closes the QUIC session with code 0 on a v2 auth. The client
// falls back to v1 over QUIC the same way it does over WebSocket.
func TestOldRelayFallbackToV1OverQUIC(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeQUIC))
	alice := runOldRelayFallback(t, "127.0.0.1:50924")
	assert.Equal(t, "quic", alice.Transport(), "transport")
}
