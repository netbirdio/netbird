package metrics

import (
	"context"
	"fmt"
	"io"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// otelMetrics is the OpenTelemetry implementation of ClientMetrics
type otelMetrics struct {
	reader        *sdkmetric.ManualReader
	meterProvider *sdkmetric.MeterProvider
	meter         metric.Meter

	// Static attributes applied to all metrics
	deploymentType DeploymentType

	// Connection stage duration histograms
	stageCreationToSemaphore      metric.Float64Histogram
	stageSemaphoreToSignaling     metric.Float64Histogram
	stageSignalingToConnection    metric.Float64Histogram
	stageConnectionToHandshake    metric.Float64Histogram
	stageTotalCreationToHandshake metric.Float64Histogram
}

func newOtelMetrics(deploymentType DeploymentType) metricsImplementation {
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	otel.SetMeterProvider(meterProvider)

	meter := meterProvider.Meter("netbird.client")

	stageCreationToSemaphore, err := meter.Float64Histogram(
		"netbird.peer.connection.stage.creation_to_semaphore",
		metric.WithDescription("Duration from connection creation to semaphore acquisition"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return &noopMetrics{}
	}

	stageSemaphoreToSignaling, err := meter.Float64Histogram(
		"netbird.peer.connection.stage.semaphore_to_signaling",
		metric.WithDescription("Duration from semaphore acquisition to signaling start"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return &noopMetrics{}
	}

	stageSignalingToConnection, err := meter.Float64Histogram(
		"netbird.peer.connection.stage.signaling_to_connection",
		metric.WithDescription("Duration from signaling start to connection ready"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return &noopMetrics{}
	}

	stageConnectionToHandshake, err := meter.Float64Histogram(
		"netbird.peer.connection.stage.connection_to_handshake",
		metric.WithDescription("Duration from connection ready to WireGuard handshake success"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return &noopMetrics{}
	}

	stageTotalCreationToHandshake, err := meter.Float64Histogram(
		"netbird.peer.connection.total.creation_to_handshake",
		metric.WithDescription("Total duration from connection creation to WireGuard handshake success"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return &noopMetrics{}
	}

	return &otelMetrics{
		reader:                        reader,
		meterProvider:                 meterProvider,
		meter:                         meter,
		deploymentType:                deploymentType,
		stageCreationToSemaphore:      stageCreationToSemaphore,
		stageSemaphoreToSignaling:     stageSemaphoreToSignaling,
		stageSignalingToConnection:    stageSignalingToConnection,
		stageConnectionToHandshake:    stageConnectionToHandshake,
		stageTotalCreationToHandshake: stageTotalCreationToHandshake,
	}
}

// RecordConnectionStages records the duration of each connection stage from timestamps
func (m *otelMetrics) RecordConnectionStages(
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

	// Combine deployment type, connection type, and attempt type attributes
	attrs := metric.WithAttributes(
		attribute.String("deployment_type", m.deploymentType.String()),
		attribute.String("connection_type", connectionType.String()),
		attribute.String("attempt_type", attemptType),
	)

	m.stageCreationToSemaphore.Record(ctx, creationToSemaphore, attrs)
	m.stageSemaphoreToSignaling.Record(ctx, semaphoreToSignaling, attrs)
	m.stageSignalingToConnection.Record(ctx, signalingToConnection, attrs)
	m.stageConnectionToHandshake.Record(ctx, connectionToHandshake, attrs)
	m.stageTotalCreationToHandshake.Record(ctx, totalDuration, attrs)
}

// Export writes metrics in Prometheus text format
func (m *otelMetrics) Export(w io.Writer) error {
	if m.reader == nil {
		return fmt.Errorf("metrics reader not initialized")
	}

	// Collect current metrics
	var rm metricdata.ResourceMetrics
	if err := m.reader.Collect(context.Background(), &rm); err != nil {
		return fmt.Errorf("failed to collect metrics: %w", err)
	}

	// Iterate through scope metrics and write in Prometheus format
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			// Write HELP line
			if _, err := fmt.Fprintf(w, "# HELP %s %s\n", m.Name, m.Description); err != nil {
				return err
			}

			// Write TYPE line
			if _, err := fmt.Fprintf(w, "# TYPE %s histogram\n", m.Name); err != nil {
				return err
			}

			// Handle histogram data
			if hist, ok := m.Data.(metricdata.Histogram[float64]); ok {
				for _, dp := range hist.DataPoints {
					// Build label string from attributes
					labelStr := ""
					if len(dp.Attributes.ToSlice()) > 0 {
						labels := ""
						for _, attr := range dp.Attributes.ToSlice() {
							if labels != "" {
								labels += ","
							}
							labels += fmt.Sprintf("%s=\"%s\"", attr.Key, attr.Value.AsString())
						}
						labelStr = labels
					}

					// Write bucket counts
					cumulativeCount := uint64(0)
					for i, bound := range dp.Bounds {
						cumulativeCount += dp.BucketCounts[i]
						bucketLabel := labelStr
						if bucketLabel != "" {
							bucketLabel += ","
						}
						bucketLabel += fmt.Sprintf("le=\"%g\"", bound)
						if _, err := fmt.Fprintf(w, "%s_bucket{%s} %d\n",
							m.Name, bucketLabel, cumulativeCount); err != nil {
							return err
						}
					}

					// Write +Inf bucket (last bucket count)
					if len(dp.BucketCounts) > len(dp.Bounds) {
						cumulativeCount += dp.BucketCounts[len(dp.BucketCounts)-1]
					}
					bucketLabel := labelStr
					if bucketLabel != "" {
						bucketLabel += ","
					}
					bucketLabel += "le=\"+Inf\""
					if _, err := fmt.Fprintf(w, "%s_bucket{%s} %d\n",
						m.Name, bucketLabel, cumulativeCount); err != nil {
						return err
					}

					// Write sum
					if labelStr != "" {
						if _, err := fmt.Fprintf(w, "%s_sum{%s} %g\n", m.Name, labelStr, dp.Sum); err != nil {
							return err
						}
					} else {
						if _, err := fmt.Fprintf(w, "%s_sum %g\n", m.Name, dp.Sum); err != nil {
							return err
						}
					}

					// Write count
					if labelStr != "" {
						if _, err := fmt.Fprintf(w, "%s_count{%s} %d\n", m.Name, labelStr, dp.Count); err != nil {
							return err
						}
					} else {
						if _, err := fmt.Fprintf(w, "%s_count %d\n", m.Name, dp.Count); err != nil {
							return err
						}
					}
				}
			}

			// Empty line between metrics
			if _, err := fmt.Fprintf(w, "\n"); err != nil {
				return err
			}
		}
	}

	return nil
}
