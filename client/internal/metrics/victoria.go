package metrics

import (
	"context"
	"fmt"
	"io"

	"github.com/VictoriaMetrics/metrics"
)

// victoriaMetrics is the VictoriaMetrics implementation of ClientMetrics
type victoriaMetrics struct {
	// Static attributes applied to all metrics
	deploymentType DeploymentType

	// Metrics set for managing all metrics
	set *metrics.Set
}

func newVictoriaMetrics(deploymentType DeploymentType) metricsImplementation {
	return &victoriaMetrics{
		deploymentType: deploymentType,
		set:            metrics.NewSet(),
	}
}

// RecordConnectionStages records the duration of each connection stage from timestamps
func (m *victoriaMetrics) RecordConnectionStages(
	ctx context.Context,
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

	if !timestamps.Created.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		totalDuration = timestamps.WgHandshakeSuccess.Sub(timestamps.Created).Seconds()
	}

	// Determine attempt type
	attemptType := "initial"
	if isReconnection {
		attemptType = "reconnection"
	}

	connTypeStr := connectionType.String()

	// Record observations using histograms
	m.set.GetOrCreateHistogram(
		m.getMetricName("netbird_peer_connection_stage_creation_to_semaphore", connTypeStr, attemptType),
	).Update(creationToSemaphore)

	m.set.GetOrCreateHistogram(
		m.getMetricName("netbird_peer_connection_stage_semaphore_to_signaling", connTypeStr, attemptType),
	).Update(semaphoreToSignaling)

	m.set.GetOrCreateHistogram(
		m.getMetricName("netbird_peer_connection_stage_signaling_to_connection", connTypeStr, attemptType),
	).Update(signalingToConnection)

	m.set.GetOrCreateHistogram(
		m.getMetricName("netbird_peer_connection_stage_connection_to_handshake", connTypeStr, attemptType),
	).Update(connectionToHandshake)

	m.set.GetOrCreateHistogram(
		m.getMetricName("netbird_peer_connection_total_creation_to_handshake", connTypeStr, attemptType),
	).Update(totalDuration)
}

// getMetricName constructs a metric name with labels
func (m *victoriaMetrics) getMetricName(baseName, connectionType, attemptType string) string {
	return fmt.Sprintf(`%s{deployment_type=%q,connection_type=%q,attempt_type=%q}`,
		baseName,
		m.deploymentType.String(),
		connectionType,
		attemptType,
	)
}

// Export writes metrics in Prometheus text format
func (m *victoriaMetrics) Export(w io.Writer) error {
	if m.set == nil {
		return fmt.Errorf("metrics set not initialized")
	}

	// Write metrics in Prometheus format
	m.set.WritePrometheus(w)
	return nil
}
