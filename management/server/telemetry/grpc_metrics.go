package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const AccountIDLabel = "account_id"
const HighLatencyThreshold = time.Second * 7

// GRPCMetrics are gRPC server metrics
type GRPCMetrics struct {
	meter                          metric.Meter
	syncRequestsCounter            metric.Int64Counter
	syncRequestsBlockedCounter     metric.Int64Counter
	loginRequestsCounter           metric.Int64Counter
	loginRequestsBlockedCounter    metric.Int64Counter
	loginRequestHighLatencyCounter metric.Int64Counter
	getKeyRequestsCounter          metric.Int64Counter
	activeStreamsGauge             metric.Int64ObservableGauge
	syncRequestDuration            metric.Int64Histogram
	loginRequestDuration           metric.Int64Histogram
	channelQueueLength             metric.Int64Histogram
	ctx                            context.Context
}

// NewGRPCMetrics creates new GRPCMetrics struct and registers common metrics of the gRPC server
func NewGRPCMetrics(ctx context.Context, meter metric.Meter) (*GRPCMetrics, error) {
	syncRequestsCounter, err := meter.Int64Counter("management.grpc.sync.request.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of sync gRPC requests from the peers to establish a connection and receive network map updates (update channel)"),
	)
	if err != nil {
		return nil, err
	}

	syncRequestsBlockedCounter, err := meter.Int64Counter("management.grpc.sync.request.blocked.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of sync gRPC requests from blocked peers"),
	)
	if err != nil {
		return nil, err
	}

	loginRequestsCounter, err := meter.Int64Counter("management.grpc.login.request.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of login gRPC requests from the peers to authenticate and receive initial configuration and relay credentials"),
	)
	if err != nil {
		return nil, err
	}

	loginRequestsBlockedCounter, err := meter.Int64Counter("management.grpc.login.request.blocked.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of login gRPC requests from blocked peers"),
	)
	if err != nil {
		return nil, err
	}

	loginRequestHighLatencyCounter, err := meter.Int64Counter("management.grpc.login.request.high.latency.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of login gRPC requests from the peers that took longer than the threshold to authenticate and receive initial configuration and relay credentials"),
	)
	if err != nil {
		return nil, err
	}

	getKeyRequestsCounter, err := meter.Int64Counter("management.grpc.key.request.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of key gRPC requests from the peers to get the server's public WireGuard key"),
	)
	if err != nil {
		return nil, err
	}

	activeStreamsGauge, err := meter.Int64ObservableGauge("management.grpc.connected.streams",
		metric.WithUnit("1"),
		metric.WithDescription("Number of active peer streams connected to the gRPC server"),
	)
	if err != nil {
		return nil, err
	}

	syncRequestDuration, err := meter.Int64Histogram("management.grpc.sync.request.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of the sync gRPC requests from the peers to establish a connection and receive network map updates (update channel)"),
	)
	if err != nil {
		return nil, err
	}

	loginRequestDuration, err := meter.Int64Histogram("management.grpc.login.request.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of the login gRPC requests from the peers to authenticate and receive initial configuration and relay credentials"),
	)
	if err != nil {
		return nil, err
	}

	// We use histogram here as we have multiple channel at the same time and we want to see a slice at any given time
	// Then we should be able to extract min, manx, mean and the percentiles.
	// TODO(yury): This needs custom bucketing as we are interested in the values from 0 to server.channelBufferSize (100)
	channelQueue, err := meter.Int64Histogram(
		"management.grpc.updatechannel.queue",
		metric.WithDescription("Number of update messages piling up in the update channel queue"),
		metric.WithUnit("length"),
	)
	if err != nil {
		return nil, err
	}

	return &GRPCMetrics{
		meter:                          meter,
		syncRequestsCounter:            syncRequestsCounter,
		syncRequestsBlockedCounter:     syncRequestsBlockedCounter,
		loginRequestsCounter:           loginRequestsCounter,
		loginRequestsBlockedCounter:    loginRequestsBlockedCounter,
		loginRequestHighLatencyCounter: loginRequestHighLatencyCounter,
		getKeyRequestsCounter:          getKeyRequestsCounter,
		activeStreamsGauge:             activeStreamsGauge,
		syncRequestDuration:            syncRequestDuration,
		loginRequestDuration:           loginRequestDuration,
		channelQueueLength:             channelQueue,
		ctx:                            ctx,
	}, err
}

// CountSyncRequest counts the number of gRPC sync requests coming to the gRPC API
func (grpcMetrics *GRPCMetrics) CountSyncRequest() {
	grpcMetrics.syncRequestsCounter.Add(grpcMetrics.ctx, 1)
}

// CountSyncRequestBlocked counts the number of gRPC sync requests from blocked peers
func (grpcMetrics *GRPCMetrics) CountSyncRequestBlocked() {
	grpcMetrics.syncRequestsBlockedCounter.Add(grpcMetrics.ctx, 1)
}

// CountGetKeyRequest counts the number of gRPC get server key requests coming to the gRPC API
func (grpcMetrics *GRPCMetrics) CountGetKeyRequest() {
	grpcMetrics.getKeyRequestsCounter.Add(grpcMetrics.ctx, 1)
}

// CountLoginRequest counts the number of gRPC login requests coming to the gRPC API
func (grpcMetrics *GRPCMetrics) CountLoginRequest() {
	grpcMetrics.loginRequestsCounter.Add(grpcMetrics.ctx, 1)
}

// CountLoginRequestBlocked counts the number of gRPC login requests from blocked peers
func (grpcMetrics *GRPCMetrics) CountLoginRequestBlocked() {
	grpcMetrics.loginRequestsBlockedCounter.Add(grpcMetrics.ctx, 1)
}

// CountLoginRequestDuration counts the duration of the login gRPC requests
func (grpcMetrics *GRPCMetrics) CountLoginRequestDuration(duration time.Duration, accountID string) {
	grpcMetrics.loginRequestDuration.Record(grpcMetrics.ctx, duration.Milliseconds())
	if duration > HighLatencyThreshold {
		grpcMetrics.loginRequestHighLatencyCounter.Add(grpcMetrics.ctx, 1, metric.WithAttributes(attribute.String(AccountIDLabel, accountID)))
	}
}

// CountSyncRequestDuration counts the duration of the sync gRPC requests
func (grpcMetrics *GRPCMetrics) CountSyncRequestDuration(duration time.Duration, accountID string) {
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
