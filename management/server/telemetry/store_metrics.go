package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
)

// StoreMetrics represents all metrics related to the Store
type StoreMetrics struct {
	globalLockAcquisitionDurationMicro syncint64.Histogram
	globalLockAcquisitionDurationMs    syncint64.Histogram
	persistenceDurationMicro           syncint64.Histogram
	persistenceDurationMs              syncint64.Histogram
	ctx                                context.Context
}

// NewStoreMetrics creates an instance of StoreMetrics
func NewStoreMetrics(ctx context.Context, meter metric.Meter) (*StoreMetrics, error) {
	globalLockAcquisitionDurationMicro, err := meter.SyncInt64().Histogram("management.store.global.lock.acquisition.duration.micro",
		instrument.WithUnit("microseconds"))
	if err != nil {
		return nil, err
	}

	globalLockAcquisitionDurationMs, err := meter.SyncInt64().Histogram("management.store.global.lock.acquisition.duration.ms")
	if err != nil {
		return nil, err
	}

	persistenceDurationMicro, err := meter.SyncInt64().Histogram("management.store.persistence.duration.micro",
		instrument.WithUnit("microseconds"))
	if err != nil {
		return nil, err
	}

	persistenceDurationMs, err := meter.SyncInt64().Histogram("management.store.persistence.duration.ms")
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
