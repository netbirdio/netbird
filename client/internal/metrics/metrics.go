package metrics

import (
	"context"
	"io"
	"time"
)

// AgentInfo holds static information about the agent
type AgentInfo struct {
	DeploymentType DeploymentType
	Version        string
}

// metricsImplementation defines the internal interface for metrics implementations
type metricsImplementation interface {
	// RecordConnectionStages records connection stage metrics from timestamps
	RecordConnectionStages(
		ctx context.Context,
		connectionType ConnectionType,
		isReconnection bool,
		timestamps ConnectionStageTimestamps,
	)

	// RecordSyncDuration records how long it took to process a sync message
	RecordSyncDuration(ctx context.Context, duration time.Duration)

	// Export exports metrics in Prometheus format
	Export(w io.Writer) error
}

type ClientMetrics struct {
	impl metricsImplementation
}

// ConnectionStageTimestamps holds timestamps for each connection stage
type ConnectionStageTimestamps struct {
	Created            time.Time
	SemaphoreAcquired  time.Time
	Signaling          time.Time // First signal sent (initial) or signal received (reconnection)
	ConnectionReady    time.Time
	WgHandshakeSuccess time.Time
}

// NewClientMetrics creates a new ClientMetrics instance
// If enabled is true, uses an OpenTelemetry implementation
// If enabled is false, uses a no-op implementation
func NewClientMetrics(agentInfo AgentInfo, enabled bool) *ClientMetrics {
	var impl metricsImplementation
	if !enabled {
		impl = &noopMetrics{}
	} else {
		impl = newVictoriaMetrics(agentInfo)
	}
	return &ClientMetrics{impl: impl}
}

// RecordConnectionStages calculates stage durations from timestamps and records them
func (c *ClientMetrics) RecordConnectionStages(
	ctx context.Context,
	connectionType ConnectionType,
	isReconnection bool,
	timestamps ConnectionStageTimestamps,
) {
	c.impl.RecordConnectionStages(ctx, connectionType, isReconnection, timestamps)
}

// RecordSyncDuration records the duration of sync message processing
func (c *ClientMetrics) RecordSyncDuration(ctx context.Context, duration time.Duration) {
	c.impl.RecordSyncDuration(ctx, duration)
}

// Export exports metrics to the writer
func (c *ClientMetrics) Export(w io.Writer) error {
	return c.impl.Export(w)
}
