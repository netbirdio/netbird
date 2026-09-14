package middleware

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// Metrics is the bundle of OTel instruments emitted by the middleware
// dispatcher. The constructor falls back to a noop meter when given
// nil so tests can skip metrics wiring entirely.
type Metrics struct {
	requestsTotal         metric.Int64Counter
	durationMs            metric.Int64Histogram
	invocationsTotal      metric.Int64Counter
	errorsTotal           metric.Int64Counter
	metadataRejectedTotal metric.Int64Counter
	headerMutationBlocked metric.Int64Counter
	captureBypassTotal    metric.Int64Counter
}

// NewMetrics registers the proxy.middleware.* instruments on the
// given meter. A nil meter is treated as the global no-op provider.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("proxy.middleware.noop")
	}

	m := &Metrics{}
	var err error

	m.requestsTotal, err = meter.Int64Counter(
		"proxy.middleware.requests_total",
		metric.WithUnit("1"),
		metric.WithDescription("Middleware invocations grouped by outcome"),
	)
	if err != nil {
		return nil, err
	}

	m.durationMs, err = meter.Int64Histogram(
		"proxy.middleware.duration_ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Middleware Invoke latency"),
	)
	if err != nil {
		return nil, err
	}

	m.invocationsTotal, err = meter.Int64Counter(
		"proxy.middleware.invocations_total",
		metric.WithUnit("1"),
		metric.WithDescription("Middleware Invoke heartbeat counter"),
	)
	if err != nil {
		return nil, err
	}

	m.errorsTotal, err = meter.Int64Counter(
		"proxy.middleware.errors_total",
		metric.WithUnit("1"),
		metric.WithDescription("Middleware errors grouped by kind"),
	)
	if err != nil {
		return nil, err
	}

	m.metadataRejectedTotal, err = meter.Int64Counter(
		"proxy.middleware.metadata_rejected_total",
		metric.WithUnit("1"),
		metric.WithDescription("Middleware metadata entries rejected by the allowlist/caps"),
	)
	if err != nil {
		return nil, err
	}

	m.headerMutationBlocked, err = meter.Int64Counter(
		"proxy.middleware.header_mutation_blocked_total",
		metric.WithUnit("1"),
		metric.WithDescription("Middleware header mutations dropped by the denylist"),
	)
	if err != nil {
		return nil, err
	}

	m.captureBypassTotal, err = meter.Int64Counter(
		"proxy.middleware.capture_bypass_total",
		metric.WithUnit("1"),
		metric.WithDescription("Capture bypasses grouped by reason"),
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// IncRequest increments proxy.middleware.requests_total with the
// middleware, target, and outcome labels.
func (m *Metrics) IncRequest(ctx context.Context, middlewareID, targetID, outcome string) {
	if m == nil {
		return
	}
	m.requestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("middleware", middlewareID),
		attribute.String("target_id", targetID),
		attribute.String("outcome", outcome),
	))
}

// ObserveDuration records the middleware Invoke latency in milliseconds.
func (m *Metrics) ObserveDuration(ctx context.Context, middlewareID string, ms int64) {
	if m == nil {
		return
	}
	m.durationMs.Record(ctx, ms, metric.WithAttributes(attribute.String("middleware", middlewareID)))
}

// IncInvocation increments the heartbeat counter regardless of outcome.
func (m *Metrics) IncInvocation(ctx context.Context, middlewareID string) {
	if m == nil {
		return
	}
	m.invocationsTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("middleware", middlewareID)))
}

// IncError increments the error counter with the given failure kind label.
func (m *Metrics) IncError(ctx context.Context, middlewareID, kind string) {
	if m == nil {
		return
	}
	m.errorsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("middleware", middlewareID),
		attribute.String("kind", kind),
	))
}

// IncMetadataRejected increments the rejected-metadata counter for a reason.
func (m *Metrics) IncMetadataRejected(ctx context.Context, middlewareID, reason string) {
	if m == nil {
		return
	}
	m.metadataRejectedTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("middleware", middlewareID),
		attribute.String("reason", reason),
	))
}

// IncHeaderMutationBlocked increments the blocked-header counter.
func (m *Metrics) IncHeaderMutationBlocked(ctx context.Context, middlewareID, header string) {
	if m == nil {
		return
	}
	m.headerMutationBlocked.Add(ctx, 1, metric.WithAttributes(
		attribute.String("middleware", middlewareID),
		attribute.String("header", header),
	))
}

// IncCaptureBypass increments the capture-bypass counter for a reason.
func (m *Metrics) IncCaptureBypass(ctx context.Context, targetID, reason string) {
	if m == nil {
		return
	}
	m.captureBypassTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("target_id", targetID),
		attribute.String("reason", reason),
	))
}
