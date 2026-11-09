//go:build !js

package metrics

import (
	"context"
	"io"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// prometheusMetrics mirrors recorded client metrics into a Prometheus
// registry for the local /metrics endpoint, then delegates to the wrapped
// implementation. Export and Reset pass through untouched: Prometheus
// metrics are cumulative and pull-based.
type prometheusMetrics struct {
	next     metricsImplementation
	registry *prometheus.Registry

	connectionStages  *prometheus.HistogramVec
	syncDuration      prometheus.Histogram
	syncPhaseDuration *prometheus.HistogramVec
	loginDuration     *prometheus.HistogramVec
}

func newPrometheusMetrics(next metricsImplementation) *prometheusMetrics {
	connectionBuckets := []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

	m := &prometheusMetrics{
		next:     next,
		registry: prometheus.NewRegistry(),
		connectionStages: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "netbird_peer_connection_stage_duration_seconds",
			Help:    "Duration of peer connection establishment stages.",
			Buckets: connectionBuckets,
		}, []string{"stage", "connection_type", "attempt_type"}),
		syncDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "netbird_sync_duration_seconds",
			Help:    "Duration of management sync message processing.",
			Buckets: prometheus.DefBuckets,
		}),
		syncPhaseDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "netbird_sync_phase_duration_seconds",
			Help:    "Duration of individual sync processing phases.",
			Buckets: prometheus.DefBuckets,
		}, []string{"phase"}),
		loginDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "netbird_login_duration_seconds",
			Help:    "Duration of logins to the management service.",
			Buckets: prometheus.DefBuckets,
		}, []string{"success"}),
	}

	m.registry.MustRegister(m.connectionStages, m.syncDuration, m.syncPhaseDuration, m.loginDuration)
	return m
}

// Gatherer returns the registry holding the mirrored metrics.
func (m *prometheusMetrics) Gatherer() prometheus.Gatherer {
	return m.registry
}

// RecordConnectionStages implements metricsImplementation.
func (m *prometheusMetrics) RecordConnectionStages(
	ctx context.Context,
	agentInfo AgentInfo,
	connectionPairID string,
	connectionType ConnectionType,
	isReconnection bool,
	timestamps ConnectionStageTimestamps,
) {
	attempt := attemptType(isReconnection)
	connType := connectionType.String()

	signalingToConnection, connectionToWgHandshake, total := timestamps.Durations()
	if signalingToConnection > 0 {
		m.connectionStages.WithLabelValues("signaling_to_connection", connType, attempt).Observe(signalingToConnection)
	}
	if connectionToWgHandshake > 0 {
		m.connectionStages.WithLabelValues("connection_to_wg_handshake", connType, attempt).Observe(connectionToWgHandshake)
	}
	if total > 0 {
		m.connectionStages.WithLabelValues("total", connType, attempt).Observe(total)
	}

	m.next.RecordConnectionStages(ctx, agentInfo, connectionPairID, connectionType, isReconnection, timestamps)
}

// RecordSyncDuration implements metricsImplementation.
func (m *prometheusMetrics) RecordSyncDuration(ctx context.Context, agentInfo AgentInfo, duration time.Duration) {
	m.syncDuration.Observe(duration.Seconds())
	m.next.RecordSyncDuration(ctx, agentInfo, duration)
}

// RecordSyncPhase implements metricsImplementation.
func (m *prometheusMetrics) RecordSyncPhase(ctx context.Context, agentInfo AgentInfo, phase string, duration time.Duration) {
	m.syncPhaseDuration.WithLabelValues(phase).Observe(duration.Seconds())
	m.next.RecordSyncPhase(ctx, agentInfo, phase, duration)
}

// RecordLoginDuration implements metricsImplementation.
func (m *prometheusMetrics) RecordLoginDuration(ctx context.Context, agentInfo AgentInfo, duration time.Duration, success bool) {
	m.loginDuration.WithLabelValues(strconv.FormatBool(success)).Observe(duration.Seconds())
	m.next.RecordLoginDuration(ctx, agentInfo, duration, success)
}

// Export implements metricsImplementation by delegating to the wrapped
// implementation; Prometheus metrics are pulled via the registry instead.
func (m *prometheusMetrics) Export(w io.Writer) error {
	return m.next.Export(w)
}

// Reset implements metricsImplementation by delegating to the wrapped
// implementation; Prometheus metrics must not be cleared on push.
func (m *prometheusMetrics) Reset() {
	m.next.Reset()
}
