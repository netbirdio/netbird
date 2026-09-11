package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

// EphemeralPeersMetrics tracks the ephemeral peer cleanup pipeline: how
// many peers are currently scheduled for deletion, how many tick runs
// the cleaner has performed, how many peers it has removed, and how
// many delete batches failed.
type EphemeralPeersMetrics struct {
	ctx context.Context

	pending      metric.Int64UpDownCounter
	cleanupRuns  metric.Int64Counter
	peersCleaned metric.Int64Counter
	errors       metric.Int64Counter
}

// NewEphemeralPeersMetrics constructs the ephemeral cleanup counters.
func NewEphemeralPeersMetrics(ctx context.Context, meter metric.Meter) (*EphemeralPeersMetrics, error) {
	pending, err := meter.Int64UpDownCounter("management.ephemeral.peers.pending",
		metric.WithUnit("1"),
		metric.WithDescription("Number of ephemeral peers currently waiting to be cleaned up"))
	if err != nil {
		return nil, err
	}

	cleanupRuns, err := meter.Int64Counter("management.ephemeral.cleanup.runs.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of ephemeral cleanup ticks that processed at least one peer"))
	if err != nil {
		return nil, err
	}

	peersCleaned, err := meter.Int64Counter("management.ephemeral.peers.cleaned.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Total number of ephemeral peers deleted by the cleanup loop"))
	if err != nil {
		return nil, err
	}

	errors, err := meter.Int64Counter("management.ephemeral.cleanup.errors.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of ephemeral cleanup batches (per account) that failed to delete"))
	if err != nil {
		return nil, err
	}

	return &EphemeralPeersMetrics{
		ctx:          ctx,
		pending:      pending,
		cleanupRuns:  cleanupRuns,
		peersCleaned: peersCleaned,
		errors:       errors,
	}, nil
}

// All methods are nil-receiver safe so callers that haven't wired metrics
// (tests, self-hosted with metrics off) can invoke them unconditionally.

// IncPending bumps the pending gauge when a peer is added to the cleanup list.
func (m *EphemeralPeersMetrics) IncPending() {
	if m == nil {
		return
	}
	m.pending.Add(m.ctx, 1)
}

// AddPending bumps the pending gauge by n — used at startup when the
// initial set of ephemeral peers is loaded from the store.
func (m *EphemeralPeersMetrics) AddPending(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.pending.Add(m.ctx, n)
}

// DecPending decreases the pending gauge — used both when a peer reconnects
// before its deadline (removed from the list) and when a cleanup tick
// actually deletes it.
func (m *EphemeralPeersMetrics) DecPending(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.pending.Add(m.ctx, -n)
}

// CountCleanupRun records one cleanup pass that processed >0 peers. Idle
// ticks (nothing to do) deliberately don't increment so the rate
// reflects useful work.
func (m *EphemeralPeersMetrics) CountCleanupRun() {
	if m == nil {
		return
	}
	m.cleanupRuns.Add(m.ctx, 1)
}

// CountPeersCleaned records the number of peers a single tick deleted.
func (m *EphemeralPeersMetrics) CountPeersCleaned(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.peersCleaned.Add(m.ctx, n)
}

// CountCleanupError records a failed delete batch.
func (m *EphemeralPeersMetrics) CountCleanupError() {
	if m == nil {
		return
	}
	m.errors.Add(m.ctx, 1)
}
