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
	ctx context.Context,
	agentInfo AgentInfo,
	connectionType ConnectionType,
	isReconnection bool,
	timestamps ConnectionStageTimestamps,
) {
	// Calculate stage durations
	var creationToSemaphore, semaphoreToSignaling, signalingToConnection, connectionToHandshake, totalDuration float64

	if !timestamps.Created.IsZero() && !timestamps.SemaphoreAcquired.IsZero() {
		creationToSemaphore = timestamps.SemaphoreAcquired.Sub(timestamps.Created).Seconds()
	}

	if !timestamps.SemaphoreAcquired.IsZero() && !timestamps.Signaling.IsZero() {
		semaphoreToSignaling = timestamps.Signaling.Sub(timestamps.SemaphoreAcquired).Seconds()
	}

	if !timestamps.Signaling.IsZero() && !timestamps.ConnectionReady.IsZero() {
		signalingToConnection = timestamps.ConnectionReady.Sub(timestamps.Signaling).Seconds()
	}

	if !timestamps.ConnectionReady.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		connectionToHandshake = timestamps.WgHandshakeSuccess.Sub(timestamps.ConnectionReady).Seconds()
	}

	// Calculate total duration:
	// For initial connections: Created → WgHandshakeSuccess
	// For reconnections: Signaling → WgHandshakeSuccess (since Created is not tracked)
	if !timestamps.Created.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		totalDuration = timestamps.WgHandshakeSuccess.Sub(timestamps.Created).Seconds()
	} else if !timestamps.Signaling.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		totalDuration = timestamps.WgHandshakeSuccess.Sub(timestamps.Signaling).Seconds()
	}

	// Determine attempt type
	attemptType := "initial"
	if isReconnection {
		attemptType = "reconnection"
	}

	connTypeStr := connectionType.String()

	// Record observations using histograms
	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_stage_creation_to_semaphore", connTypeStr, attemptType),
	).Update(creationToSemaphore)

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_stage_semaphore_to_signaling", connTypeStr, attemptType),
	).Update(semaphoreToSignaling)

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_stage_signaling_to_connection", connTypeStr, attemptType),
	).Update(signalingToConnection)

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_stage_connection_to_handshake", connTypeStr, attemptType),
	).Update(connectionToHandshake)

	m.set.GetOrCreateHistogram(
		m.getMetricName(agentInfo, "netbird_peer_connection_total_creation_to_handshake", connTypeStr, attemptType),
	).Update(totalDuration)

	log.Tracef("peer connection metrics [%s, %s, %s]: creation→semaphore: %.3fs, semaphore→signaling: %.3fs, signaling→connection: %.3fs, connection→handshake: %.3fs, total: %.3fs",
		agentInfo.DeploymentType.String(), connTypeStr, attemptType,
		creationToSemaphore, semaphoreToSignaling, signalingToConnection, connectionToHandshake,
		totalDuration)
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
func (m *victoriaMetrics) RecordSyncDuration(ctx context.Context, agentInfo AgentInfo, duration time.Duration) {
	metricName := fmt.Sprintf(`netbird_sync_duration_seconds{deployment_type=%q,version=%q,os=%q}`,
		agentInfo.DeploymentType.String(),
		agentInfo.Version,
		agentInfo.OS,
	)

	m.set.GetOrCreateHistogram(metricName).Update(duration.Seconds())
}

// Export writes metrics in Prometheus text format with HELP comments
func (m *victoriaMetrics) Export(w io.Writer) error {
	if m.set == nil {
		return fmt.Errorf("metrics set not initialized")
	}

	// Write metrics in Prometheus format
	m.set.WritePrometheus(w)
	return nil
}
