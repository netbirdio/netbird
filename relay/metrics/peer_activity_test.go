package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
)

func TestMetrics_PeerIsIdleUntilItSendsTraffic(t *testing.T) {
	m, err := NewMetrics(context.Background(), noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)

	activity := NewPeerActivity()
	m.PeerConnected("peer", "quic", activity)
	active, idle := m.calculateActiveIdleConnections()
	assert.Equal(t, int64(0), active, "a peer without traffic must not count as active")
	assert.Equal(t, int64(1), idle, "a peer without traffic must count as idle")

	activity.Mark()
	active, idle = m.calculateActiveIdleConnections()
	assert.Equal(t, int64(1), active, "a peer with recent traffic must count as active")
	assert.Equal(t, int64(0), idle, "a peer with recent traffic must not count as idle")

	m.PeerDisconnected("peer", "quic", activity)
	active, idle = m.calculateActiveIdleConnections()
	assert.Equal(t, int64(0), active, "a disconnected peer must not count as active")
	assert.Equal(t, int64(0), idle, "a disconnected peer must not count as idle")
}

func TestMetrics_OldConnectionDoesNotRemoveItsReplacement(t *testing.T) {
	m, err := NewMetrics(context.Background(), noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)

	replaced := NewPeerActivity()
	m.PeerConnected("peer", "quic", replaced)
	replacement := NewPeerActivity()
	m.PeerConnected("peer", "quic", replacement)
	replacement.Mark()

	m.PeerDisconnected("peer", "quic", replaced)
	active, idle := m.calculateActiveIdleConnections()
	assert.Equal(t, int64(1), active, "the new connection of the peer must stay counted")
	assert.Equal(t, int64(0), idle, "the new connection of the peer has traffic")

	m.PeerDisconnected("peer", "quic", replacement)
	active, idle = m.calculateActiveIdleConnections()
	assert.Equal(t, int64(0), active+idle, "no connection of the peer is left")
}
