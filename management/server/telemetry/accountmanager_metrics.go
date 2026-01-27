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

	return &AccountManagerMetrics{
		ctx:                          ctx,
		getPeerNetworkMapDurationMs:  getPeerNetworkMapDurationMs,
		updateAccountPeersDurationMs: updateAccountPeersDurationMs,
		networkMapObjectCount:        networkMapObjectCount,
		peerMetaUpdateCount:          peerMetaUpdateCount,
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
