package metrics

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type metricSample struct {
	name      string
	value     float64
	timestamp time.Time
}

// victoriaMetrics collects metric events as timestamped samples.
// Each event is recorded with its exact timestamp, pushed once, then cleared.
type victoriaMetrics struct {
	mu      sync.Mutex
	samples []metricSample
}

func newVictoriaMetrics() metricsImplementation {
	return &victoriaMetrics{}
}

func (m *victoriaMetrics) RecordConnectionStages(
	_ context.Context,
	agentInfo AgentInfo,
	connectionType ConnectionType,
	isReconnection bool,
	timestamps ConnectionStageTimestamps,
) {
	var signalingReceivedToConnection, connectionToWgHandshake, totalDuration float64

	if !timestamps.SignalingReceived.IsZero() && !timestamps.ConnectionReady.IsZero() {
		signalingReceivedToConnection = timestamps.ConnectionReady.Sub(timestamps.SignalingReceived).Seconds()
	}

	if !timestamps.ConnectionReady.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		connectionToWgHandshake = timestamps.WgHandshakeSuccess.Sub(timestamps.ConnectionReady).Seconds()
	}

	if !timestamps.SignalingReceived.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		totalDuration = timestamps.WgHandshakeSuccess.Sub(timestamps.SignalingReceived).Seconds()
	}

	attemptType := "initial"
	if isReconnection {
		attemptType = "reconnection"
	}

	connTypeStr := connectionType.String()
	labels := fmt.Sprintf(`deployment_type=%q,connection_type=%q,attempt_type=%q,version=%q,os=%q`,
		agentInfo.DeploymentType.String(),
		connTypeStr,
		attemptType,
		agentInfo.Version,
		agentInfo.OS,
	)

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.samples = append(m.samples,
		metricSample{
			name:      fmt.Sprintf("netbird_peer_connection_stage_signaling_received_to_connection_seconds{%s}", labels),
			value:     signalingReceivedToConnection,
			timestamp: now,
		},
		metricSample{
			name:      fmt.Sprintf("netbird_peer_connection_stage_connection_to_wg_handshake_seconds{%s}", labels),
			value:     connectionToWgHandshake,
			timestamp: now,
		},
		metricSample{
			name:      fmt.Sprintf("netbird_peer_connection_total_seconds{%s}", labels),
			value:     totalDuration,
			timestamp: now,
		},
		metricSample{
			name:      fmt.Sprintf("netbird_peer_connection_count{%s}", labels),
			value:     1,
			timestamp: now,
		},
	)

	log.Tracef("peer connection metrics [%s, %s, %s]: signalingReceived→connection: %.3fs, connection→wg_handshake: %.3fs, total: %.3fs",
		agentInfo.DeploymentType.String(), connTypeStr, attemptType, signalingReceivedToConnection, connectionToWgHandshake, totalDuration)
}

func (m *victoriaMetrics) RecordSyncDuration(_ context.Context, agentInfo AgentInfo, duration time.Duration) {
	name := fmt.Sprintf(`netbird_sync_duration_seconds{deployment_type=%q,version=%q,os=%q}`,
		agentInfo.DeploymentType.String(),
		agentInfo.Version,
		agentInfo.OS,
	)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.samples = append(m.samples, metricSample{
		name:      name,
		value:     duration.Seconds(),
		timestamp: time.Now(),
	})
}

// Export writes pending samples in Prometheus text format with explicit timestamps.
// Format: metric_name{labels} value timestamp_ms
func (m *victoriaMetrics) Export(w io.Writer) error {
	m.mu.Lock()
	samples := make([]metricSample, len(m.samples))
	copy(samples, m.samples)
	m.mu.Unlock()

	for _, s := range samples {
		if _, err := fmt.Fprintf(w, "%s %g %d\n", s.name, s.value, s.timestamp.UnixMilli()); err != nil {
			return err
		}
	}
	return nil
}

// Reset clears pending samples after a successful push
func (m *victoriaMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.samples = m.samples[:0]
}
