package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
)

// StoreMetrics represents all metrics related to the FileStore
type StoreMetrics struct {
	globalLockAcquisitionDuration syncint64.Histogram
	persistenceDuration           syncint64.Histogram
	ctx                           context.Context
}

// NewStoreMetrics creates an instance of StoreMetrics
func NewStoreMetrics(ctx context.Context, meter metric.Meter) (*StoreMetrics, error) {
	globalLockAcquisitionDuration, err := meter.SyncInt64().Histogram("management.store.global.lock.acquisition.duration.micro",
		instrument.WithUnit("microseconds"))
	if err != nil {
		return nil, err
	}
	persistenceDuration, err := meter.SyncInt64().Histogram("management.store.persistence.duration.micro",
		instrument.WithUnit("microseconds"))
	if err != nil {
		return nil, err
	}

	return &StoreMetrics{
		globalLockAcquisitionDuration: globalLockAcquisitionDuration,
		persistenceDuration:           persistenceDuration,
		ctx:                           ctx,
	}, nil
}

// CountGlobalLockAcquisitionDuration counts the duration of the global lock acquisition
func (metrics *StoreMetrics) CountGlobalLockAcquisitionDuration(duration time.Duration) {
	metrics.globalLockAcquisitionDuration.Record(metrics.ctx, duration.Microseconds())
}

// CountPersistenceDuration counts the duration of a store persistence operation
func (metrics *StoreMetrics) CountPersistenceDuration(duration time.Duration) {
	metrics.persistenceDuration.Record(metrics.ctx, duration.Microseconds())
}
