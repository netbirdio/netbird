package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// AccountManagerMetrics represents all metrics related to the AccountManager
type AccountManagerMetrics struct {
	ctx                          context.Context
	updateAccountPeersDurationMs metric.Float64Histogram
	getPeerNetworkMapDurationMs  metric.Float64Histogram
	networkMapObjectCount        metric.Int64Histogram
	peerMetaUpdateCount          metric.Int64Counter

	shadowLegacySizeBytes     metric.Int64Histogram
	shadowComponentsSizeBytes metric.Int64Histogram
	shadowSavingsPercent      metric.Int64Histogram
}

// NewAccountManagerMetrics creates an instance of AccountManagerMetrics
func NewAccountManagerMetrics(ctx context.Context, meter metric.Meter) (*AccountManagerMetrics, error) {
	updateAccountPeersDurationMs, err := meter.Float64Histogram("management.account.update.account.peers.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithExplicitBucketBoundaries(
			0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000,
		),
		metric.WithDescription("Duration of triggering the account peers update and preparing the required data for the network map being sent to the clients"))
	if err != nil {
		return nil, err
	}

	getPeerNetworkMapDurationMs, err := meter.Float64Histogram("management.account.get.peer.network.map.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithExplicitBucketBoundaries(
			0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000,
		),
		metric.WithDescription("Duration of calculating the peer network map that is sent to the clients"))
	if err != nil {
		return nil, err
	}

	networkMapObjectCount, err := meter.Int64Histogram("management.account.network.map.object.count",
		metric.WithUnit("objects"),
		metric.WithExplicitBucketBoundaries(
			50, 100, 200, 500, 1000, 2500, 5000, 10000,
		),
		metric.WithDescription("Number of objects in the network map like peers, routes, firewall rules, etc. that are sent to the clients"))
	if err != nil {
		return nil, err
	}

	peerMetaUpdateCount, err := meter.Int64Counter("management.account.peer.meta.update.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of updates with new meta data from the peers"))
	if err != nil {
		return nil, err
	}

	shadowLegacySizeBytes, err := meter.Int64Histogram("management.account.shadow.legacy.size.bytes",
		metric.WithUnit("bytes"),
		metric.WithExplicitBucketBoundaries(
			1024, 5120, 10240, 51200, 102400, 512000, 1048576, 5242880, 10485760,
		),
		metric.WithDescription("Size of legacy network map in bytes"))
	if err != nil {
		return nil, err
	}

	shadowComponentsSizeBytes, err := meter.Int64Histogram("management.account.shadow.components.size.bytes",
		metric.WithUnit("bytes"),
		metric.WithExplicitBucketBoundaries(
			1024, 5120, 10240, 51200, 102400, 512000, 1048576, 5242880, 10485760,
		),
		metric.WithDescription("Size of components-based network map in bytes"))
	if err != nil {
		return nil, err
	}

	shadowSavingsPercent, err := meter.Int64Histogram("management.account.shadow.savings.percent",
		metric.WithUnit("percent"),
		metric.WithExplicitBucketBoundaries(
			0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
		),
		metric.WithDescription("Percentage of bandwidth savings with components-based network map"))
	if err != nil {
		return nil, err
	}

	return &AccountManagerMetrics{
		ctx:                          ctx,
		getPeerNetworkMapDurationMs:  getPeerNetworkMapDurationMs,
		updateAccountPeersDurationMs: updateAccountPeersDurationMs,
		networkMapObjectCount:        networkMapObjectCount,
		peerMetaUpdateCount:          peerMetaUpdateCount,

		shadowLegacySizeBytes:     shadowLegacySizeBytes,
		shadowComponentsSizeBytes: shadowComponentsSizeBytes,
		shadowSavingsPercent:      shadowSavingsPercent,
	}, nil

}

// CountUpdateAccountPeersDuration counts the duration of updating account peers
func (metrics *AccountManagerMetrics) CountUpdateAccountPeersDuration(duration time.Duration) {
	metrics.updateAccountPeersDurationMs.Record(metrics.ctx, float64(duration.Nanoseconds())/1e6)
}

// CountGetPeerNetworkMapDuration counts the duration of getting the peer network map
func (metrics *AccountManagerMetrics) CountGetPeerNetworkMapDuration(duration time.Duration) {
	metrics.getPeerNetworkMapDurationMs.Record(metrics.ctx, float64(duration.Nanoseconds())/1e6)
}

// CountNetworkMapObjects counts the number of network map objects
func (metrics *AccountManagerMetrics) CountNetworkMapObjects(count int64) {
	metrics.networkMapObjectCount.Record(metrics.ctx, count)
}

// CountPeerMetUpdate counts the number of peer meta updates
func (metrics *AccountManagerMetrics) CountPeerMetUpdate() {
	metrics.peerMetaUpdateCount.Add(metrics.ctx, 1)
}

// CountShadowLegacySize records the size of legacy network map in bytes
func (metrics *AccountManagerMetrics) CountShadowLegacySize(bytes int64) {
	metrics.shadowLegacySizeBytes.Record(metrics.ctx, bytes)
}

// CountShadowComponentsSize records the size of components-based network map in bytes
func (metrics *AccountManagerMetrics) CountShadowComponentsSize(bytes int64) {
	metrics.shadowComponentsSizeBytes.Record(metrics.ctx, bytes)
}

// CountShadowSavingsPercent records the percentage of bandwidth savings
func (metrics *AccountManagerMetrics) CountShadowSavingsPercent(percent int64) {
	metrics.shadowSavingsPercent.Record(metrics.ctx, percent)
}
