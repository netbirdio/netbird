package metrics

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/VictoriaMetrics/metrics"
	log "github.com/sirupsen/logrus"
)

// victoriaMetrics is the VictoriaMetrics implementation of ClientMetrics
type victoriaMetrics struct {
	// Metrics set for managing all metrics
	set *metrics.Set
}

func newVictoriaMetrics() metricsImplementation {
	return &victoriaMetrics{
		set: metrics.NewSet(),
	}
}

// RecordConnectionStages records the duration of each connection stage from timestamps
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

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_stage_signaling_received_to_connection", connTypeStr, attemptType),
	).Update(signalingReceivedToConnection)

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_stage_connection_to_wg_handshake", connTypeStr, attemptType),
	).Update(connectionToWgHandshake)

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_total_creation_to_wg_handshake", connTypeStr, attemptType),
	).Update(totalDuration)

	log.Tracef("peer connection metrics [%s, %s, %s]: signalingReceived→connection: %.3fs, connection→wg_handshake: %.3fs, total: %.3fs",
		agentInfo.DeploymentType.String(), connTypeStr, attemptType, signalingReceivedToConnection, connectionToWgHandshake, totalDuration)
}

// getMetricName constructs a metric name with labels
func (m *victoriaMetrics) getMetricName(agentInfo AgentInfo, baseName, connectionType, attemptType string) string {
	return fmt.Sprintf(`%s{deployment_type=%q,connection_type=%q,attempt_type=%q,version=%q,os=%q}`,
		baseName,
		agentInfo.DeploymentType.String(),
		connectionType,
		attemptType,
		agentInfo.Version,
		agentInfo.OS,
	)
}

// RecordSyncDuration records the duration of sync message processing
func (m *victoriaMetrics) RecordSyncDuration(_ context.Context, agentInfo AgentInfo, duration time.Duration) {
	metricName := fmt.Sprintf(`netbird_sync_duration_seconds{deployment_type=%q,version=%q,os=%q}`,
		agentInfo.DeploymentType.String(),
		agentInfo.Version,
		agentInfo.OS,
	)

	m.set.GetOrCreateHistogram(metricName).Update(duration.Seconds())
}

// Export writes metrics in Prometheus text format
func (m *victoriaMetrics) Export(w io.Writer) error {
	if m.set == nil {
		return fmt.Errorf("metrics set not initialized")
	}

	m.set.WritePrometheus(w)
	return nil
}

// Reset clears all collected metrics
func (m *victoriaMetrics) Reset() {
	m.set.UnregisterAllMetrics()
}
