package metrics

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfluxDBMetrics_RecordAndExport(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	agentInfo := AgentInfo{
		DeploymentType: DeploymentTypeCloud,
		Version:        "1.0.0",
		OS:             "linux",
		Arch:           "amd64",
		peerID:         "abc123",
	}

	ts := ConnectionStageTimestamps{
		SignalingReceived:  time.Now().Add(-3 * time.Second),
		ConnectionReady:    time.Now().Add(-2 * time.Second),
		WgHandshakeSuccess: time.Now().Add(-1 * time.Second),
	}

	m.RecordConnectionStages(context.Background(), agentInfo, "pair123", ConnectionTypeICE, false, ts)

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "netbird_peer_connection,")
	assert.Contains(t, output, "connection_to_wg_handshake_seconds=")
	assert.Contains(t, output, "signaling_to_connection_seconds=")
	assert.Contains(t, output, "total_seconds=")
}

func TestInfluxDBMetrics_ExportDeterministicFieldOrder(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	agentInfo := AgentInfo{
		DeploymentType: DeploymentTypeCloud,
		Version:        "1.0.0",
		OS:             "linux",
		Arch:           "amd64",
		peerID:         "abc123",
	}

	ts := ConnectionStageTimestamps{
		SignalingReceived:  time.Now().Add(-3 * time.Second),
		ConnectionReady:    time.Now().Add(-2 * time.Second),
		WgHandshakeSuccess: time.Now().Add(-1 * time.Second),
	}

	// Record multiple times and verify consistent field order
	for i := 0; i < 10; i++ {
		m.RecordConnectionStages(context.Background(), agentInfo, "pair123", ConnectionTypeICE, false, ts)
	}

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 10)

	// Extract field portion from each line and verify they're all identical
	var fieldSections []string
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 3)
		require.Len(t, parts, 3, "each line should have measurement, fields, timestamp")
		fieldSections = append(fieldSections, parts[1])
	}

	for i := 1; i < len(fieldSections); i++ {
		assert.Equal(t, fieldSections[0], fieldSections[i], "field order should be deterministic across samples")
	}

	// Fields should be alphabetically sorted
	assert.True(t, strings.HasPrefix(fieldSections[0], "connection_to_wg_handshake_seconds="),
		"fields should be sorted: connection_to_wg < signaling_to < total")
}

func TestInfluxDBMetrics_RecordSyncDuration(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	agentInfo := AgentInfo{
		DeploymentType: DeploymentTypeSelfHosted,
		Version:        "2.0.0",
		OS:             "darwin",
		Arch:           "arm64",
		peerID:         "def456",
	}

	m.RecordSyncDuration(context.Background(), agentInfo, 1500*time.Millisecond)

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "netbird_sync,")
	assert.Contains(t, output, "duration_seconds=1.5")
	assert.Contains(t, output, "deployment_type=selfhosted")
}

func TestInfluxDBMetrics_Reset(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	agentInfo := AgentInfo{
		DeploymentType: DeploymentTypeCloud,
		Version:        "1.0.0",
		OS:             "linux",
		Arch:           "amd64",
		peerID:         "abc123",
	}

	m.RecordSyncDuration(context.Background(), agentInfo, time.Second)

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String())

	m.Reset()

	buf.Reset()
	err = m.Export(&buf)
	require.NoError(t, err)
	assert.Empty(t, buf.String(), "should be empty after reset")
}

func TestInfluxDBMetrics_ExportEmpty(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestInfluxDBMetrics_TrimByAge(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	m.mu.Lock()
	m.samples = append(m.samples, influxSample{
		measurement: "old",
		tags:        "t=1",
		fields:      map[string]float64{"v": 1},
		timestamp:   time.Now().Add(-maxSampleAge - time.Hour),
	})
	m.trimLocked()
	remaining := len(m.samples)
	m.mu.Unlock()

	assert.Equal(t, 0, remaining, "old samples should be trimmed")
}

func TestInfluxDBMetrics_RecordLoginDuration(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	agentInfo := AgentInfo{
		DeploymentType: DeploymentTypeCloud,
		Version:        "1.0.0",
		OS:             "linux",
		Arch:           "amd64",
		peerID:         "abc123",
	}

	m.RecordLoginDuration(context.Background(), agentInfo, 2500*time.Millisecond, true)

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "netbird_login,")
	assert.Contains(t, output, "duration_seconds=2.5")
	assert.Contains(t, output, "result=success")
}

func TestInfluxDBMetrics_RecordLoginDurationFailure(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	agentInfo := AgentInfo{
		DeploymentType: DeploymentTypeSelfHosted,
		Version:        "1.0.0",
		OS:             "darwin",
		Arch:           "arm64",
		peerID:         "xyz789",
	}

	m.RecordLoginDuration(context.Background(), agentInfo, 5*time.Second, false)

	var buf bytes.Buffer
	err := m.Export(&buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "netbird_login,")
	assert.Contains(t, output, "result=failure")
	assert.Contains(t, output, "deployment_type=selfhosted")
}

func TestInfluxDBMetrics_TrimBySize(t *testing.T) {
	m := newInfluxDBMetrics().(*influxDBMetrics)

	maxSamples := maxBufferSize / estimatedSampleSize
	m.mu.Lock()
	for i := 0; i < maxSamples+100; i++ {
		m.samples = append(m.samples, influxSample{
			measurement: "test",
			tags:        "t=1",
			fields:      map[string]float64{"v": float64(i)},
			timestamp:   time.Now(),
		})
	}
	m.trimLocked()
	remaining := len(m.samples)
	m.mu.Unlock()

	assert.Equal(t, maxSamples, remaining, "should trim to max samples")
}
