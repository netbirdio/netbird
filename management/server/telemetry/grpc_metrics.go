package telemetry

import (
	"context"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/instrument/asyncint64"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
)

// GRPCMetrics are gRPC server metrics
type GRPCMetrics struct {
	meter                 metric.Meter
	syncRequestsCounter   syncint64.Counter
	loginRequestsCounter  syncint64.Counter
	getKeyRequestsCounter syncint64.Counter
	activeStreamsGauge    asyncint64.Gauge
	ctx                   context.Context
}

// NewGRPCMetrics creates new GRPCMetrics struct and registers common metrics of the gRPC server
func NewGRPCMetrics(ctx context.Context, meter metric.Meter) (*GRPCMetrics, error) {
	syncRequestsCounter, err := meter.SyncInt64().Counter("management.grpc.sync.request.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	loginRequestsCounter, err := meter.SyncInt64().Counter("management.grpc.login.request.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}
	getKeyRequestsCounter, err := meter.SyncInt64().Counter("management.grpc.key.request.counter", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	activeStreamsGauge, err := meter.AsyncInt64().Gauge("management.grpc.connected.streams", instrument.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	return &GRPCMetrics{
		meter:                 meter,
		syncRequestsCounter:   syncRequestsCounter,
		loginRequestsCounter:  loginRequestsCounter,
		getKeyRequestsCounter: getKeyRequestsCounter,
		activeStreamsGauge:    activeStreamsGauge,
		ctx:                   ctx,
	}, err
}

// RegisterConnectedStreams registers a function that collects number of active streams and feeds it to the metrics gauge.
func (m *GRPCMetrics) RegisterConnectedStreams(producer func() int64) error {
	if err := m.meter.RegisterCallback(
		[]instrument.Asynchronous{
			m.activeStreamsGauge,
		},
		func(ctx context.Context) {
			m.activeStreamsGauge.Observe(ctx, producer())
		},
	); err != nil {
		return err
	}

	return nil
}
