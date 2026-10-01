package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/metrics"
)

func TestMetricsStages_RecordSignalingReceived(t *testing.T) {
	s := &MetricsStages{}

	s.RecordSignalingReceived()
	ts := s.GetTimestamps()
	require.False(t, ts.SignalingReceived.IsZero())

	// Second call should not overwrite
	first := ts.SignalingReceived
	time.Sleep(time.Millisecond)
	s.RecordSignalingReceived()
	ts = s.GetTimestamps()
	assert.Equal(t, first, ts.SignalingReceived, "should keep the first signaling timestamp")
}

func TestMetricsStages_RecordConnectionReady(t *testing.T) {
	s := &MetricsStages{}

	now := time.Now()
	s.RecordConnectionReady(now)
	ts := s.GetTimestamps()
	assert.Equal(t, now, ts.ConnectionReady)

	// Second call should not overwrite
	later := now.Add(time.Second)
	s.RecordConnectionReady(later)
	ts = s.GetTimestamps()
	assert.Equal(t, now, ts.ConnectionReady, "should keep the first connection ready timestamp")
}

func TestMetricsStages_RecordWGHandshakeSuccess(t *testing.T) {
	s := &MetricsStages{}

	connReady := time.Now()
	s.RecordConnectionReady(connReady)

	handshake := connReady.Add(500 * time.Millisecond)
	s.RecordWGHandshakeSuccess(handshake)

	ts := s.GetTimestamps()
	assert.Equal(t, handshake, ts.WgHandshakeSuccess)
}

func TestMetricsStages_HandshakeBeforeConnectionReady_Normalizes(t *testing.T) {
	s := &MetricsStages{}

	connReady := time.Now()
	s.RecordConnectionReady(connReady)

	// WG handshake appears before ConnectionReady due to second-precision truncation
	handshake := connReady.Add(-100 * time.Millisecond)
	s.RecordWGHandshakeSuccess(handshake)

	ts := s.GetTimestamps()
	assert.Equal(t, connReady, ts.WgHandshakeSuccess, "should normalize to ConnectionReady when handshake appears earlier")
}

func TestMetricsStages_HandshakeIgnoredWithoutConnectionReady(t *testing.T) {
	s := &MetricsStages{}

	s.RecordWGHandshakeSuccess(time.Now())
	ts := s.GetTimestamps()
	assert.True(t, ts.WgHandshakeSuccess.IsZero(), "should not record handshake without connection ready")
}

func TestMetricsStages_HandshakeRecordedOnce(t *testing.T) {
	s := &MetricsStages{}

	connReady := time.Now()
	s.RecordConnectionReady(connReady)

	first := connReady.Add(time.Second)
	s.RecordWGHandshakeSuccess(first)

	// Second call (rekey) should be ignored
	second := connReady.Add(2 * time.Second)
	s.RecordWGHandshakeSuccess(second)

	ts := s.GetTimestamps()
	assert.Equal(t, first, ts.WgHandshakeSuccess, "should preserve first handshake, ignore rekeys")
}

func TestMetricsStages_Disconnected(t *testing.T) {
	s := &MetricsStages{}

	s.RecordSignalingReceived()
	s.RecordConnectionReady(time.Now())
	assert.False(t, s.IsReconnection())

	s.Disconnected()

	assert.True(t, s.IsReconnection())
	ts := s.GetTimestamps()
	assert.True(t, ts.SignalingReceived.IsZero(), "timestamps should be reset after disconnect")
	assert.True(t, ts.ConnectionReady.IsZero(), "timestamps should be reset after disconnect")
	assert.True(t, ts.WgHandshakeSuccess.IsZero(), "timestamps should be reset after disconnect")
}

func TestMetricsStages_GetTimestamps(t *testing.T) {
	s := &MetricsStages{}

	ts := s.GetTimestamps()
	assert.Equal(t, metrics.ConnectionStageTimestamps{}, ts)

	now := time.Now()
	s.RecordSignalingReceived()
	s.RecordConnectionReady(now)

	ts = s.GetTimestamps()
	assert.False(t, ts.SignalingReceived.IsZero())
	assert.Equal(t, now, ts.ConnectionReady)
	assert.True(t, ts.WgHandshakeSuccess.IsZero())
}
