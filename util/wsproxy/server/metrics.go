package server

import (
	"context"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// MetricsRecorder defines the interface for recording proxy metrics
type MetricsRecorder interface {
	// RecordConnection records a new connection
	RecordConnection(ctx context.Context)
	// RecordDisconnection records a connection closing
	RecordDisconnection(ctx context.Context)
	// RecordBytesTransferred records bytes transferred in a direction
	RecordBytesTransferred(ctx context.Context, direction string, bytes int64)
	// RecordError records an error
	RecordError(ctx context.Context, errorType string)
}

// NoOpMetricsRecorder is a no-op implementation that does nothing
type NoOpMetricsRecorder struct{}

func (n NoOpMetricsRecorder) RecordConnection(ctx context.Context) {
	// no-op
}
func (n NoOpMetricsRecorder) RecordDisconnection(ctx context.Context) {
	// no-op
}
func (n NoOpMetricsRecorder) RecordBytesTransferred(ctx context.Context, direction string, bytes int64) {
	// no-op
}
func (n NoOpMetricsRecorder) RecordError(ctx context.Context, errorType string) {
	// no-op
}

// Recorder implements MetricsRecorder using OpenTelemetry
type Recorder struct {
	activeConnections metric.Int64UpDownCounter
	bytesTransferred  metric.Int64Counter
	errors            metric.Int64Counter
}

// NewMetricsRecorder creates a new OpenTelemetry-based metrics recorder
func NewMetricsRecorder(meter metric.Meter) (*Recorder, error) {
	activeConnections, err := meter.Int64UpDownCounter(
		"wsproxy_active_connections",
		metric.WithDescription("Number of active WebSocket proxy connections"),
	)
	if err != nil {
		return nil, err
	}

	bytesTransferred, err := meter.Int64Counter(
		"wsproxy_bytes_transferred_total",
		metric.WithDescription("Total bytes transferred through the proxy"),
	)
	if err != nil {
		return nil, err
	}

	errors, err := meter.Int64Counter(
		"wsproxy_errors_total",
		metric.WithDescription("Total number of proxy errors"),
	)
	if err != nil {
		return nil, err
	}

	return &Recorder{
		activeConnections: activeConnections,
		bytesTransferred:  bytesTransferred,
		errors:            errors,
	}, nil
}

func (o *Recorder) RecordConnection(ctx context.Context) {
	o.activeConnections.Add(ctx, 1)
}

func (o *Recorder) RecordDisconnection(ctx context.Context) {
	o.activeConnections.Add(ctx, -1)
}

func (o *Recorder) RecordBytesTransferred(ctx context.Context, direction string, bytes int64) {
	o.bytesTransferred.Add(ctx, bytes, metric.WithAttributes(
		attribute.String("direction", direction),
	))
}

func (o *Recorder) RecordError(ctx context.Context, errorType string) {
	o.errors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("error_type", errorType),
	))
}

// Option defines functional options for the Proxy
type Option func(*Config)

// WithMetrics sets a custom metrics recorder
func WithMetrics(recorder MetricsRecorder) Option {
	return func(c *Config) {
		c.MetricsRecorder = recorder
	}
}

// WithOTelMeter creates and sets an OpenTelemetry metrics recorder
func WithOTelMeter(meter metric.Meter) Option {
	return func(c *Config) {
		if recorder, err := NewMetricsRecorder(meter); err == nil {
			c.MetricsRecorder = recorder
		} else {
			log.Warnf("Failed to create OTel metrics recorder: %v", err)
		}
	}
}
