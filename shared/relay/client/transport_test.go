package client

import (
	"net"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
)

// closeTrackingConn records whether Close was called; only Close is exercised.
type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (c *closeTrackingConn) Close() error {
	c.closed = true
	return nil
}

func TestTransportModeFromEnv(t *testing.T) {
	tests := []struct {
		value string
		want  TransportMode
	}{
		{"", TransportModeAuto},
		{"auto", TransportModeAuto},
		{"quic", TransportModeQUIC},
		{"QUIC", TransportModeQUIC},
		{"ws", TransportModeWS},
		{" Ws ", TransportModeWS},
		{"prefer-quic", TransportModePreferQUIC},
		{"prefer-ws", TransportModePreferWS},
		{"garbage", TransportModeAuto},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(EnvRelayTransport, tc.value)
			if tc.value == "" {
				os.Unsetenv(EnvRelayTransport)
			}
			assert.Equal(t, tc.want, transportModeFromEnv())
		})
	}
}

func TestTransportFallbackRecordAndExpiry(t *testing.T) {
	const url = "rels://relay.example:443"
	f := newTransportFallback()

	assert.False(t, f.avoidDatagramSized(url), "no fallback recorded yet")

	d := f.recordFailure(url)
	assert.Equal(t, transportFallbackBase, d, "first failure pins for the base window")
	assert.True(t, f.avoidDatagramSized(url), "datagram-sized transport avoided within the window")

	// A second failure while still inside the window must not grow the window.
	d = f.recordFailure(url)
	assert.LessOrEqual(t, d, transportFallbackBase, "still within the active window")
	require.NotNil(t, f.entries[url])
	assert.Equal(t, transportFallbackBase, f.entries[url].duration, "duration unchanged inside window")

	// Expire the window: datagram-sized transport allowed again.
	f.entries[url].until = time.Now().Add(-time.Second)
	assert.False(t, f.avoidDatagramSized(url), "window expired, datagram-sized transport allowed")
}

func TestTransportFallbackGrowsOnRepeat(t *testing.T) {
	const url = "rels://relay.example:443"
	f := newTransportFallback()

	want := transportFallbackBase
	for i := range 6 {
		d := f.recordFailure(url)
		assert.Equal(t, want, d, "window after %d expiries", i)

		// expire the window so the next failure is treated as a repeat
		f.entries[url].until = time.Now().Add(-time.Second)

		want = min(want*2, transportFallbackMax)
	}

	assert.Equal(t, transportFallbackMax, f.entries[url].duration, "window caps at the max")
}

func TestOnDatagramTooLargeAuto(t *testing.T) {
	const url = "rels://relay.example:443"
	t.Setenv(EnvRelayTransport, string(TransportModeAuto))

	tf := newTransportFallback()
	c := &Client{
		log:               log.WithField("test", t.Name()),
		connectionURL:     url,
		transportFallback: tf,
	}
	conn := &closeTrackingConn{}

	c.onDatagramTooLarge(conn, netErr.ErrDatagramTooLarge)

	assert.True(t, conn.closed, "connection closed to force reconnect")
	assert.True(t, tf.avoidDatagramSized(url), "fallback recorded for the server")

	// A second oversized datagram on the same connection must not re-close.
	conn.closed = false
	c.onDatagramTooLarge(conn, netErr.ErrDatagramTooLarge)
	assert.False(t, conn.closed, "single fallback per connection")
}

func TestOnDatagramTooLargeQUICPinned(t *testing.T) {
	const url = "rels://relay.example:443"
	t.Setenv(EnvRelayTransport, string(TransportModeQUIC))

	tf := newTransportFallback()
	c := &Client{
		log:               log.WithField("test", t.Name()),
		connectionURL:     url,
		transportFallback: tf,
	}
	conn := &closeTrackingConn{}

	c.onDatagramTooLarge(conn, netErr.ErrDatagramTooLarge)

	assert.False(t, conn.closed, "QUIC pin keeps the connection, no fallback redial")
	assert.False(t, tf.avoidDatagramSized(url), "QUIC pin records no fallback")
}

func TestTransportFallbackPerServer(t *testing.T) {
	f := newTransportFallback()
	f.recordFailure("rels://a.example:443")

	assert.True(t, f.avoidDatagramSized("rels://a.example:443"))
	assert.False(t, f.avoidDatagramSized("rels://b.example:443"), "fallback is scoped to one server")
}
