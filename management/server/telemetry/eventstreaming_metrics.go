package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	labelTargetPlatform      = attribute.Key("target_platform")
	labelAccountID           = attribute.Key("account_id")
	labelHTTPStatusCode      = attribute.Key("http_status_code")
	labelFailureReason       = attribute.Key("failure_reason")
	labelManagerAction       = attribute.Key("manager_action")
	labelManagerActionResult = attribute.Key("manager_action_result")
	labelEventStreamStatus   = attribute.Key("event_stream_status")
)

type EventStreamingMetrics struct {
	ctx context.Context

	eventsSentTotal                 metric.Int64Counter
	eventsFailedTotal               metric.Int64Counter
	deliveryAttemptsTotal           metric.Int64Counter
	eventQueueSize                  metric.Int64UpDownCounter
	activeWorkers                   metric.Int64UpDownCounter
	deliveryDurationMilliseconds    metric.Float64Histogram
	managerActionTotal              metric.Int64Counter
	integrationEventsProcessedTotal metric.Int64Counter
}

func NewEventStreamingMetrics(ctx context.Context, meter metric.Meter) (*EventStreamingMetrics, error) {
	var err error
	metrics := &EventStreamingMetrics{ctx: ctx}

	metrics.eventsSentTotal, err = meter.Int64Counter(
		"eventstreaming.events.sent.total",
		metric.WithDescription("Total number of events successfully sent."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	metrics.eventsFailedTotal, err = meter.Int64Counter(
		"eventstreaming.events.failed.total",
		metric.WithDescription("Total number of events that failed to be sent after all retries."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	metrics.deliveryAttemptsTotal, err = meter.Int64Counter(
		"eventstreaming.delivery.attempts.total",
		metric.WithDescription("Total number of delivery attempts for events."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	metrics.eventQueueSize, err = meter.Int64UpDownCounter(
		"eventstreaming.event.queue.size",
		metric.WithDescription("Current number of events in the Generic HTTP client's delivery queue."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	metrics.activeWorkers, err = meter.Int64UpDownCounter(
		"eventstreaming.active.workers",
		metric.WithDescription("Current number of active workers in the Generic HTTP client."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	metrics.deliveryDurationMilliseconds, err = meter.Float64Histogram(
		"eventstreaming.delivery.duration.ms",
		metric.WithDescription("Duration from when an event is picked from the queue until it's successfully sent or finally fails for Generic HTTP."),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(10, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000),
	)
	if err != nil {
		return nil, err
	}

	metrics.managerActionTotal, err = meter.Int64Counter(
		"eventstreaming.manager.action.total",
		metric.WithDescription("Total number of integration management actions (create, update, delete, test)."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	metrics.integrationEventsProcessedTotal, err = meter.Int64Counter(
		"eventstreaming.integration.events.processed.total",
		metric.WithDescription("Total number of events processed by the streaming store, indicating outcome."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

func (m *EventStreamingMetrics) RecordGenericHTTPSentEvent(accountID, platform, statusCode string) {
	m.eventsSentTotal.Add(m.ctx, 1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
			labelHTTPStatusCode.String(statusCode),
		),
	)
}

func (m *EventStreamingMetrics) RecordGenericHTTPFailedEvent(accountID, platform, reason string) {
	m.eventsFailedTotal.Add(m.ctx, 1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
			labelFailureReason.String(reason),
		),
	)
}

func (m *EventStreamingMetrics) RecordGenericHTTPDeliveryAttempt(accountID, platform string) {
	m.deliveryAttemptsTotal.Add(m.ctx, 1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
		),
	)
}

func (m *EventStreamingMetrics) UpdateGenericHTTPEventQueueSize(accountID, platform string, count int64, add bool) {
	if add {
		m.eventQueueSize.Add(m.ctx, count,
			metric.WithAttributes(
				labelAccountID.String(accountID),
				labelTargetPlatform.String(platform),
			),
		)
	} else {
		m.eventQueueSize.Add(m.ctx, -count,
			metric.WithAttributes(
				labelAccountID.String(accountID),
				labelTargetPlatform.String(platform),
			),
		)
	}
}

func (m *EventStreamingMetrics) AddActiveWorker(accountID, platform string) {
	m.activeWorkers.Add(m.ctx, 1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
		),
	)
}

func (m *EventStreamingMetrics) RemoveActiveWorker(accountID, platform string) {
	m.activeWorkers.Add(m.ctx, -1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
		),
	)
}

func (m *EventStreamingMetrics) RecordGenericHTTPDeliveryDuration(accountID, platform string, duration time.Duration) {
	m.deliveryDurationMilliseconds.Record(m.ctx, float64(duration.Milliseconds()),
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
		),
	)
}

func (m *EventStreamingMetrics) RecordManagerAction(accountID, action, platform, resultStatus string) {
	m.managerActionTotal.Add(m.ctx, 1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelManagerAction.String(action),
			labelTargetPlatform.String(platform),
			labelManagerActionResult.String(resultStatus),
		),
	)
}

func (m *EventStreamingMetrics) RecordIntegrationEventProcessed(accountID, platform, statusValue string) {
	m.integrationEventsProcessedTotal.Add(m.ctx, 1,
		metric.WithAttributes(
			labelAccountID.String(accountID),
			labelTargetPlatform.String(platform),
			labelEventStreamStatus.String(statusValue),
		),
	)
}
