package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// AccountManagerMetrics represents all metrics related to the AccountManager
type AccountManagerMetrics struct {
	ctx                          context.Context
	updateAccountPeersDurationMs metric.Float64Histogram
	updateAccountPeersCounter    metric.Int64Counter
	nmapCounter                  metric.Int64Counter
	getPeerNetworkMapDurationMs  metric.Float64Histogram
	networkMapObjectCount        metric.Int64Histogram
	peerMetaUpdateCount          metric.Int64Counter
	peerStatusUpdateCounter      metric.Int64Counter
	peerStatusUpdateDurationMs   metric.Float64Histogram
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

	updateAccountPeersCounter, err := meter.Int64Counter("management.account.update.account.peers.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of account peers updates triggered, labeled by resource and operation"))
	if err != nil {
		return nil, err
	}

	nmapCounter, err := meter.Int64Counter("management.network.map.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of network maps computed, labeled by resource and operation trigger"))
	if err != nil {
		return nil, err
	}

	peerMetaUpdateCount, err := meter.Int64Counter("management.account.peer.meta.update.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of updates with new meta data from the peers"))
	if err != nil {
		return nil, err
	}

	// peerStatusUpdateCounter records every attempt to mark a peer as connected or disconnected
	peerStatusUpdateCounter, err := meter.Int64Counter("management.account.peer.status.update.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of peer status update attempts, labeled by operation (connect|disconnect) and outcome (applied|stale|error|peer_not_found)"))
	if err != nil {
		return nil, err
	}

	peerStatusUpdateDurationMs, err := meter.Float64Histogram("management.account.peer.status.update.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithExplicitBucketBoundaries(
			1, 5, 15, 25, 50, 100, 250, 500, 1000, 2000, 5000,
		),
		metric.WithDescription("Duration of a peer status update (fence UPDATE + post-write side effects), labeled by operation"))
	if err != nil {
		return nil, err
	}

	return &AccountManagerMetrics{
		ctx:                          ctx,
		getPeerNetworkMapDurationMs:  getPeerNetworkMapDurationMs,
		updateAccountPeersDurationMs: updateAccountPeersDurationMs,
		updateAccountPeersCounter:    updateAccountPeersCounter,
		networkMapObjectCount:        networkMapObjectCount,
		peerMetaUpdateCount:          peerMetaUpdateCount,
		peerStatusUpdateCounter:      peerStatusUpdateCounter,
		peerStatusUpdateDurationMs:   peerStatusUpdateDurationMs,
		nmapCounter:                  nmapCounter,
	}, nil

}

// PeerStatusOperation labels the kind of fence-locked peer status write.
type PeerStatusOperation string

// PeerStatusOutcome labels how a fence-locked peer status write resolved.
type PeerStatusOutcome string

const (
	PeerStatusConnect    PeerStatusOperation = "connect"
	PeerStatusDisconnect PeerStatusOperation = "disconnect"

	// PeerStatusApplied — the fence WHERE matched and the UPDATE landed.
	PeerStatusApplied PeerStatusOutcome = "applied"
	// PeerStatusStale — the fence WHERE rejected the write because a
	// newer session has already taken ownership (connect: stored token
	// >= incoming; disconnect: stored token != incoming).
	PeerStatusStale PeerStatusOutcome = "stale"
	// PeerStatusError — the store returned a non-NotFound error.
	PeerStatusError PeerStatusOutcome = "error"
	// PeerStatusPeerNotFound — the peer lookup failed (the peer was
	// deleted between the gRPC sync handshake and the status write).
	PeerStatusPeerNotFound PeerStatusOutcome = "peer_not_found"
)

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

// CountUpdateAccountPeersTriggered increments the counter for account peers updates with resource and operation labels.
func (metrics *AccountManagerMetrics) CountUpdateAccountPeersTriggered(resource, operation string) {
	metrics.updateAccountPeersCounter.Add(metrics.ctx, 1,
		metric.WithAttributes(
			attribute.String("resource", resource),
			attribute.String("operation", operation),
		),
	)
}

// CountNmapTriggered increments the counter for calculated network maps with resource and operation labels.
func (metrics *AccountManagerMetrics) CountNmapTriggered(resource, operation string) {
	metrics.nmapCounter.Add(metrics.ctx, 1,
		metric.WithAttributes(
			attribute.String("resource", resource),
			attribute.String("operation", operation),
		),
	)
}

// CountPeerMetUpdate counts the number of peer meta updates
func (metrics *AccountManagerMetrics) CountPeerMetUpdate() {
	metrics.peerMetaUpdateCount.Add(metrics.ctx, 1)
}

// CountPeerStatusUpdate increments the connect/disconnect counter,
// labeled by operation and outcome. Both labels are bounded enums.
func (metrics *AccountManagerMetrics) CountPeerStatusUpdate(op PeerStatusOperation, outcome PeerStatusOutcome) {
	metrics.peerStatusUpdateCounter.Add(metrics.ctx, 1,
		metric.WithAttributes(
			attribute.String("operation", string(op)),
			attribute.String("outcome", string(outcome)),
		),
	)
}

// RecordPeerStatusUpdateDuration records the wall-clock time spent
// running a peer status update (including post-write side effects),
// labeled by operation.
func (metrics *AccountManagerMetrics) RecordPeerStatusUpdateDuration(op PeerStatusOperation, d time.Duration) {
	metrics.peerStatusUpdateDurationMs.Record(metrics.ctx, float64(d.Nanoseconds())/1e6,
		metric.WithAttributes(attribute.String("operation", string(op))),
	)
}
