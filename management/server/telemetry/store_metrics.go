package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// StoreMetrics represents all metrics related to the Store
type StoreMetrics struct {
	globalLockAcquisitionDurationMicro metric.Int64Histogram
	globalLockAcquisitionDurationMs    metric.Int64Histogram
	persistenceDurationMicro           metric.Int64Histogram
	persistenceDurationMs              metric.Int64Histogram
	transactionDurationMs              metric.Int64Histogram
	queryDurationMs                    metric.Int64Histogram
	queryCounter                       metric.Int64Counter
	ctx                                context.Context
}

// NewStoreMetrics creates an instance of StoreMetrics
func NewStoreMetrics(ctx context.Context, meter metric.Meter) (*StoreMetrics, error) {
	globalLockAcquisitionDurationMicro, err := meter.Int64Histogram("management.store.global.lock.acquisition.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to acquire the global lock in the store to block all other requests to the store"),
	)
	if err != nil {
		return nil, err
	}

	globalLockAcquisitionDurationMs, err := meter.Int64Histogram("management.store.global.lock.acquisition.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of how long a process holds the acquired global lock in the store"),
	)
	if err != nil {
		return nil, err
	}

	persistenceDurationMicro, err := meter.Int64Histogram("management.store.persistence.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to save or delete an account in the store"),
	)
	if err != nil {
		return nil, err
	}

	persistenceDurationMs, err := meter.Int64Histogram("management.store.persistence.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of how long it takes to save or delete an account in the store"),
	)
	if err != nil {
		return nil, err
	}

	transactionDurationMs, err := meter.Int64Histogram("management.store.transaction.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of how long it takes to execute a transaction in the store"),
	)
	if err != nil {
		return nil, err
	}

	queryDurationMs, err := meter.Int64Histogram("management.store.query.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of database query operations with operation type and table name"),
	)
	if err != nil {
		return nil, err
	}

	queryCounter, err := meter.Int64Counter("management.store.query.count",
		metric.WithDescription("Count of database query operations with operation type, table name, and status"),
	)
	if err != nil {
		return nil, err
	}

	return &StoreMetrics{
		globalLockAcquisitionDurationMicro: globalLockAcquisitionDurationMicro,
		globalLockAcquisitionDurationMs:    globalLockAcquisitionDurationMs,
		persistenceDurationMicro:           persistenceDurationMicro,
		persistenceDurationMs:              persistenceDurationMs,
		transactionDurationMs:              transactionDurationMs,
		queryDurationMs:                    queryDurationMs,
		queryCounter:                       queryCounter,
		ctx:                                ctx,
	}, nil
}

// CountGlobalLockAcquisitionDuration counts the duration of the global lock acquisition
func (metrics *StoreMetrics) CountGlobalLockAcquisitionDuration(duration time.Duration) {
	metrics.globalLockAcquisitionDurationMicro.Record(metrics.ctx, duration.Microseconds())
	metrics.globalLockAcquisitionDurationMs.Record(metrics.ctx, duration.Milliseconds())
}

// CountPersistenceDuration counts the duration of a store persistence operation
func (metrics *StoreMetrics) CountPersistenceDuration(duration time.Duration) {
	metrics.persistenceDurationMicro.Record(metrics.ctx, duration.Microseconds())
	metrics.persistenceDurationMs.Record(metrics.ctx, duration.Milliseconds())
}

// CountTransactionDuration counts the duration of a store persistence operation
func (metrics *StoreMetrics) CountTransactionDuration(duration time.Duration) {
	metrics.transactionDurationMs.Record(metrics.ctx, duration.Milliseconds())
}

// CountQuery records a database query operation with its duration, operation type, table, and status
func (metrics *StoreMetrics) CountQuery(operation, table, status string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.String("table", table),
		attribute.String("status", status),
	}

	metrics.queryDurationMs.Record(metrics.ctx, duration.Milliseconds(), metric.WithAttributes(attrs...))
	metrics.queryCounter.Add(metrics.ctx, 1, metric.WithAttributes(attrs...))
}

// CountStoreOperation records a store operation with its method name, status, and duration
func (metrics *StoreMetrics) CountStoreOperation(method, status string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("status", status),
	}

	metrics.queryDurationMs.Record(metrics.ctx, duration.Milliseconds(), metric.WithAttributes(attrs...))
	metrics.queryCounter.Add(metrics.ctx, 1, metric.WithAttributes(attrs...))
}
