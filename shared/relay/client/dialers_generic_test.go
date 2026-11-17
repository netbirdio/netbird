//go:build !js

package client

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/quic"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

// TestDatagramSizedCapability locks the capability the generic fallback relies
// on: QUIC is datagram-sized, WebSocket is not.
func TestDatagramSizedCapability(t *testing.T) {
	assert.True(t, dialer.IsDatagramSized(quic.Dialer{}), "QUIC must advertise datagram-sized")
	assert.False(t, dialer.IsDatagramSized(ws.Dialer{}), "WebSocket must not advertise datagram-sized")
}

func protocols(dialers []dialer.DialeFn) []string {
	out := make([]string, len(dialers))
	for i, d := range dialers {
		out[i] = d.Protocol()
	}
	return out
}

func TestGetDialers(t *testing.T) {
	const url = "rels://relay.example:443"

	tests := []struct {
		name     string
		mode     string
		mtu      uint16
		preferWS bool
		want     []string
	}{
		{name: "auto races quic and ws", mode: "auto", mtu: iface.DefaultMTU, want: []string{"quic", "ws"}},
		{name: "ws pinned", mode: "ws", mtu: iface.DefaultMTU, want: []string{"ws"}},
		{name: "quic pinned", mode: "quic", mtu: iface.DefaultMTU, want: []string{"quic"}},
		{name: "prefer-quic orders quic first", mode: "prefer-quic", mtu: iface.DefaultMTU, want: []string{"quic", "ws"}},
		{name: "prefer-ws orders ws first", mode: "prefer-ws", mtu: iface.DefaultMTU, want: []string{"ws", "quic"}},
		{name: "mtu above default forces ws", mode: "auto", mtu: iface.DefaultMTU + 100, want: []string{"ws"}},
		{name: "sticky fallback forces ws in auto", mode: "auto", mtu: iface.DefaultMTU, preferWS: true, want: []string{"ws"}},
		{name: "sticky fallback forces ws in prefer-quic", mode: "prefer-quic", mtu: iface.DefaultMTU, preferWS: true, want: []string{"ws"}},
		{name: "quic pin overrides sticky fallback", mode: "quic", mtu: iface.DefaultMTU, preferWS: true, want: []string{"quic"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvRelayTransport, tc.mode)
			if tc.mode == "" {
				os.Unsetenv(EnvRelayTransport)
			}

			tf := newTransportFallback()
			if tc.preferWS {
				tf.recordFailure(url)
			}

			c := &Client{
				log:               log.WithField("test", t.Name()),
				connectionURL:     url,
				mtu:               tc.mtu,
				transportFallback: tf,
			}

			assert.Equal(t, tc.want, protocols(c.getDialers(transportModeFromEnv())))
		})
	}
}

// TestStickyFallbackAfterDatagramTooLarge verifies the full chain: an oversized
// datagram records a fallback that makes the next dial pick WebSocket, the way a
// reconnect would after the connection is closed.
func TestStickyFallbackAfterDatagramTooLarge(t *testing.T) {
	const url = "rels://relay.example:443"
	t.Setenv(EnvRelayTransport, string(TransportModeAuto))

	c := &Client{
		log:               log.WithField("test", t.Name()),
		connectionURL:     url,
		mtu:               iface.DefaultMTU,
		transportFallback: newTransportFallback(),
	}

	// First dial races both transports.
	assert.Equal(t, []string{"quic", "ws"}, protocols(c.getDialers(transportModeFromEnv())))

	// An oversized datagram records the fallback for this server.
	c.onDatagramTooLarge(&closeTrackingConn{}, netErr.ErrDatagramTooLarge)

	// The reconnect now sticks to WebSocket.
	assert.Equal(t, []string{"ws"}, protocols(c.getDialers(transportModeFromEnv())))
}
