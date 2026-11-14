// Package hbmetrics counts what the aligned heartbeat does on the Management,
// Signal and relay servers, so an operator can see why a client does not align:
// heartbeats sent, phase corrections applied or ignored, corrections that hit
// the correction window, and signed phases that failed to verify.
package hbmetrics

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

const (
	// IgnoreStock: the stream has no verified signed phase, so it runs stock.
	IgnoreStock IgnoreReason = "stock"
	// IgnoreInvalid: the phase is outside the period.
	IgnoreInvalid IgnoreReason = "invalid"
	// IgnoreRateLimit: the stream already moved its tick in this tick.
	IgnoreRateLimit IgnoreReason = "rate_limit"
	// IgnoreAtWindowEdge: the correction was clamped to the window edge the
	// tick is on already.
	IgnoreAtWindowEdge IgnoreReason = "at_window_edge"
	// IgnoreOldDay: a signed phase that is not newer than the verified one.
	IgnoreOldDay IgnoreReason = "old_day"
)

const labelReason = "reason"

// ClampWarnAfter is how many corrections in a row a stream may have clamped
// before the server warns. The client asks again after two ticks with the same
// offset, so this is about six ticks.
const ClampWarnAfter = 3

// IgnoreReason says why a phase correction from a client was not applied.
type IgnoreReason string

// Metrics holds the aligned heartbeat counters of one server. A nil *Metrics
// counts nothing, so code paths without a meter need no checks.
type Metrics struct {
	heartbeats metric.Int64Counter
	applied    metric.Int64Counter
	ignored    metric.Int64Counter
	clampHits  metric.Int64Counter
	badSigs    metric.Int64Counter
}

// ClampStreak tracks the clamped corrections in a row of one stream and warns
// the first time they reach ClampWarnAfter, at most once per stream, so a
// client cannot drive the Warn log. A clock off by more than the window on a
// self-hosted Signal or relay host shows this way: the stream never aligns.
// The zero value is ready to use.
type ClampStreak struct {
	mu     sync.Mutex
	n      int
	warned bool
}

// New creates the counters on meter. Every name starts with prefix, so each
// server keeps its own naming, for example "relay_" or "management.grpc.".
func New(meter metric.Meter, prefix string) (*Metrics, error) {
	var m Metrics
	counters := []struct {
		dst  *metric.Int64Counter
		name string
		desc string
	}{
		{&m.heartbeats, "aligned_heartbeat_sent_total", "Total number of aligned heartbeats sent to clients"},
		{&m.applied, "aligned_heartbeat_corrections_applied_total", "Total number of phase corrections that moved a stream tick"},
		{&m.ignored, "aligned_heartbeat_corrections_ignored_total", "Total number of phase corrections and signed phases not applied, by reason"},
		{&m.clampHits, "aligned_heartbeat_clamp_hits_total", "Total number of phase corrections clamped to the correction window"},
		{&m.badSigs, "aligned_heartbeat_bad_signatures_total", "Total number of signed phases that failed to verify"},
	}
	for _, c := range counters {
		counter, err := meter.Int64Counter(prefix+c.name, metric.WithDescription(c.desc))
		if err != nil {
			return nil, fmt.Errorf("create counter %s: %w", prefix+c.name, err)
		}
		*c.dst = counter
	}
	return &m, nil
}

// HeartbeatSent counts one heartbeat sent.
func (m *Metrics) HeartbeatSent(ctx context.Context) {
	if m != nil {
		m.heartbeats.Add(ctx, 1)
	}
}

// CorrectionApplied counts one correction that moved a tick.
func (m *Metrics) CorrectionApplied(ctx context.Context) {
	if m != nil {
		m.applied.Add(ctx, 1)
	}
}

// CorrectionIgnored counts one correction or signed phase not applied.
func (m *Metrics) CorrectionIgnored(ctx context.Context, reason IgnoreReason) {
	if m != nil {
		m.ignored.Add(ctx, 1, metric.WithAttributes(attribute.String(labelReason, string(reason))))
	}
}

// ClampHit counts one correction clamped to the window.
func (m *Metrics) ClampHit(ctx context.Context) {
	if m != nil {
		m.clampHits.Add(ctx, 1)
	}
}

// BadSignature counts one signed phase that failed to verify.
func (m *Metrics) BadSignature(ctx context.Context) {
	if m != nil {
		m.badSigs.Add(ctx, 1)
	}
}

// Hit records a clamped correction for the stream of peer and logs the warning
// when the streak reaches ClampWarnAfter. It reports whether it warned.
func (c *ClampStreak) Hit(service, peer string) bool {
	c.mu.Lock()
	c.n++
	warn := c.n >= ClampWarnAfter && !c.warned
	if warn {
		c.warned = true
	}
	n := c.n
	c.mu.Unlock()
	if warn {
		log.Warnf("%s: %d phase corrections in a row from %s clamped to the ±%s window, "+
			"the clock of this host may be off", service, n, peer, alignedhb.CorrectionWindow)
	}
	return warn
}

// Reset ends the streak after a correction inside the window. A stream that
// already warned does not warn again.
func (c *ClampStreak) Reset() {
	c.mu.Lock()
	c.n = 0
	c.mu.Unlock()
}
