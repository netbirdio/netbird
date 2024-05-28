package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// StoreMetrics represents all metrics related to the Store
type StoreMetrics struct {
	globalLockAcquisitionDurationMicro metric.Int64Histogram
	globalLockAcquisitionDurationMs    metric.Int64Histogram
	persistenceDurationMicro           metric.Int64Histogram
	persistenceDurationMs              metric.Int64Histogram
	ctx                                context.Context
}

// NewStoreMetrics creates an instance of StoreMetrics
func NewStoreMetrics(ctx context.Context, meter metric.Meter) (*StoreMetrics, error) {
	globalLockAcquisitionDurationMicro, err := meter.Int64Histogram("management.store.global.lock.acquisition.duration.micro",
		metric.WithUnit("microseconds"))
	if err != nil {
		return nil, err
	}

	globalLockAcquisitionDurationMs, err := meter.Int64Histogram("management.store.global.lock.acquisition.duration.ms")
	if err != nil {
		return nil, err
	}

	persistenceDurationMicro, err := meter.Int64Histogram("management.store.persistence.duration.micro",
		metric.WithUnit("microseconds"))
	if err != nil {
		return nil, err
	}

	persistenceDurationMs, err := meter.Int64Histogram("management.store.persistence.duration.ms")
	if err != nil {
		return nil, err
	}

	return &StoreMetrics{
		globalLockAcquisitionDurationMicro: globalLockAcquisitionDurationMicro,
		globalLockAcquisitionDurationMs:    globalLockAcquisitionDurationMs,
		persistenceDurationMicro:           persistenceDurationMicro,
		persistenceDurationMs:              persistenceDurationMs,
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
