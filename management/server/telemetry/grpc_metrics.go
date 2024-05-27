package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// GRPCMetrics are gRPC server metrics
type GRPCMetrics struct {
	meter                 metric.Meter
	syncRequestsCounter   metric.Int64Counter
	loginRequestsCounter  metric.Int64Counter
	getKeyRequestsCounter metric.Int64Counter
	activeStreamsGauge    metric.Int64ObservableGauge
	syncRequestDuration   metric.Int64Histogram
	loginRequestDuration  metric.Int64Histogram
	channelQueueLength    metric.Int64Histogram
	ctx                   context.Context
}

// NewGRPCMetrics creates new GRPCMetrics struct and registers common metrics of the gRPC server
func NewGRPCMetrics(ctx context.Context, meter metric.Meter) (*GRPCMetrics, error) {
	syncRequestsCounter, err := meter.Int64Counter("management.grpc.sync.request.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	loginRequestsCounter, err := meter.Int64Counter("management.grpc.login.request.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	getKeyRequestsCounter, err := meter.Int64Counter("management.grpc.key.request.counter", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	activeStreamsGauge, err := meter.Int64ObservableGauge("management.grpc.connected.streams", metric.WithUnit("1"))
	if err != nil {
		return nil, err
	}

	syncRequestDuration, err := meter.Int64Histogram("management.grpc.sync.request.duration.ms", metric.WithUnit("milliseconds"))
	if err != nil {
		return nil, err
	}

	loginRequestDuration, err := meter.Int64Histogram("management.grpc.login.request.duration.ms", metric.WithUnit("milliseconds"))
	if err != nil {
		return nil, err
	}

	// We use histogram here as we have multiple channel at the same time and we want to see a slice at any given time
	// Then we should be able to extract min, manx, mean and the percentiles.
	// TODO(yury): This needs custom bucketing as we are interested in the values from 0 to server.channelBufferSize (100)
	channelQueue, err := meter.Int64Histogram(
		"management.grpc.updatechannel.queue",
		metric.WithDescription("Number of update messages in the channel queue"),
		metric.WithUnit("length"),
	)
	if err != nil {
		return nil, err
	}

	return &GRPCMetrics{
		meter:                 meter,
		syncRequestsCounter:   syncRequestsCounter,
		loginRequestsCounter:  loginRequestsCounter,
		getKeyRequestsCounter: getKeyRequestsCounter,
		activeStreamsGauge:    activeStreamsGauge,
		syncRequestDuration:   syncRequestDuration,
		loginRequestDuration:  loginRequestDuration,
		channelQueueLength:    channelQueue,
		ctx:                   ctx,
	}, err
}

// CountSyncRequest counts the number of gRPC sync requests coming to the gRPC API
func (grpcMetrics *GRPCMetrics) CountSyncRequest() {
	grpcMetrics.syncRequestsCounter.Add(grpcMetrics.ctx, 1)
}

// CountGetKeyRequest counts the number of gRPC get server key requests coming to the gRPC API
func (grpcMetrics *GRPCMetrics) CountGetKeyRequest() {
	grpcMetrics.getKeyRequestsCounter.Add(grpcMetrics.ctx, 1)
}

// CountLoginRequest counts the number of gRPC login requests coming to the gRPC API
func (grpcMetrics *GRPCMetrics) CountLoginRequest() {
	grpcMetrics.loginRequestsCounter.Add(grpcMetrics.ctx, 1)
}

// CountLoginRequestDuration counts the duration of the login gRPC requests
func (grpcMetrics *GRPCMetrics) CountLoginRequestDuration(duration time.Duration) {
	grpcMetrics.loginRequestDuration.Record(grpcMetrics.ctx, duration.Milliseconds())
}

// CountSyncRequestDuration counts the duration of the sync gRPC requests
func (grpcMetrics *GRPCMetrics) CountSyncRequestDuration(duration time.Duration) {
	grpcMetrics.syncRequestDuration.Record(grpcMetrics.ctx, duration.Milliseconds())
}

// RegisterConnectedStreams registers a function that collects number of active streams and feeds it to the metrics gauge.
func (grpcMetrics *GRPCMetrics) RegisterConnectedStreams(producer func() int64) error {
	_, err := grpcMetrics.meter.RegisterCallback(
		func(ctx context.Context, observer metric.Observer) error {
			observer.ObserveInt64(grpcMetrics.activeStreamsGauge, producer())
			return nil
		},
		grpcMetrics.activeStreamsGauge,
	)
	return err
}

// UpdateChannelQueueLength update the histogram that keep distribution of the update messages channel queue
func (metrics *GRPCMetrics) UpdateChannelQueueLength(length int) {
	metrics.channelQueueLength.Record(metrics.ctx, int64(length))
}
