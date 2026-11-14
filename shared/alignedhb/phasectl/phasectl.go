// Package phasectl holds the aligned heartbeat phase rules that Signal and relay
// apply to a stream: which signed phase it ticks on, and how far and how often
// the client may move the tick.
package phasectl

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// Phase is the aligned heartbeat schedule of one stream. A stream is stock until
// it has a verified signed phase. The client may then move the tick inside the
// correction window around that phase, once per tick. Phase is safe for
// concurrent use.
type Phase struct {
	service string
	peer    string
	metrics *hbmetrics.Metrics
	log     *log.Entry

	mu sync.Mutex
	// sched is the current schedule, nil while the stream is stock.
	sched *alignedhb.Answer
	// signed is the last verified signed phase, nil when none, and day the day
	// it was signed for.
	signed *alignedhb.Answer
	day    int64
	// correctionAllowed is set by Tick and cleared by the correction it allows.
	correctionAllowed bool
	clamps            hbmetrics.ClampStreak
}

// New returns the schedule of a stock stream. service and peer name the stream
// in the clamp warning, m counts what the rules decide and may be nil. A nil
// logger logs to the standard logger.
func New(service, peer string, m *hbmetrics.Metrics, logger *log.Entry) *Phase {
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}
	return &Phase{service: service, peer: peer, metrics: m, log: logger}
}

// Verify checks a signed phase a client handed over for the requested period.
// The period is clamped to limits first: Management signs for the clamped
// period, so a phase signed for a period outside the limits never verifies.
// The answer carries the clamped period also when the check fails, which m
// counts.
func Verify(v *phasesig.Verifier, limits alignedhb.PeriodLimits, peer messages.PeerID, requested time.Duration, signed alignedhb.SignedPhase, now time.Time, m *hbmetrics.Metrics) (alignedhb.Answer, error) {
	answer := alignedhb.Answer{Period: limits.Clamp(requested), Phase: signed.Phase}
	if v == nil {
		return answer, fmt.Errorf("no phase verifier configured")
	}
	if err := v.Verify(peer, answer.Period, signed, now); err != nil {
		m.BadSignature(context.Background())
		return answer, err
	}
	return answer, nil
}

// Start sets the signed phase the stream opened with, verified for day. Call it
// before the stream runs.
func (p *Phase) Start(answer alignedhb.Answer, day int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sched, signed := answer, answer
	p.sched, p.signed, p.day = &sched, &signed, day
}

// Schedule returns the current schedule, ok false while the stream is stock.
func (p *Phase) Schedule() (alignedhb.Answer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sched == nil {
		return alignedhb.Answer{}, false
	}
	return *p.sched, true
}

// Tick allows the next correction. Call it on each heartbeat, so the client
// corrects in answer to a heartbeat it saw.
func (p *Phase) Tick() {
	p.mu.Lock()
	p.correctionAllowed = true
	p.mu.Unlock()
}

// AcceptSigned moves the stream to next, a signed phase verified for day, and
// reports whether it did. The first one turns the stream aligned. A later one
// replaces it only for a newer day: signatures stay valid for days around
// today, so a client holding two of them could otherwise flip the tick between
// them past the correction window and the per tick limit. The same rule ignores
// a phase signed for another period on the same day, so a period change takes
// effect on the next stream.
func (p *Phase) AcceptSigned(next alignedhb.Answer, day int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.signed != nil {
		if *p.signed == next && p.day == day {
			return false
		}
		if day <= p.day {
			p.metrics.CorrectionIgnored(context.Background(), hbmetrics.IgnoreOldDay)
			p.log.Debugf("ignoring signed phase of day %d: day %d already verified", day, p.day)
			return false
		}
	}
	sched, signed := next, next
	p.sched, p.signed, p.day = &sched, &signed, day
	p.clamps.Reset()
	return true
}

// Correct moves the tick of an aligned stream to phase, limited to the
// correction window around the signed phase and to one request per tick. It
// returns the new schedule, ok false when the request changes nothing.
func (p *Phase) Correct(phase time.Duration) (_ alignedhb.Answer, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx := context.Background()
	cur := p.sched
	if p.signed == nil || cur == nil {
		p.metrics.CorrectionIgnored(ctx, hbmetrics.IgnoreStock)
		return alignedhb.Answer{}, false
	}
	if phase == cur.Phase {
		return alignedhb.Answer{}, false
	}
	if !alignedhb.ValidPhase(phase, cur.Period) {
		p.metrics.CorrectionIgnored(ctx, hbmetrics.IgnoreInvalid)
		p.log.Debugf("ignoring phase request %d ms outside period %s", phase.Milliseconds(), cur.Period)
		return alignedhb.Answer{}, false
	}
	if !p.correctionAllowed {
		p.metrics.CorrectionIgnored(ctx, hbmetrics.IgnoreRateLimit)
		p.log.Debugf("ignoring phase request %d ms: one correction per tick", phase.Milliseconds())
		return alignedhb.Answer{}, false
	}
	// A request at the window edge uses the tick too, so the clamp streak counts
	// at most one request per tick whatever the client sends.
	p.correctionAllowed = false
	clamped, hit := alignedhb.ClampPhase(phase, p.signed.Phase, cur.Period)
	p.recordClamp(phase, clamped, hit)
	if clamped == cur.Phase {
		p.metrics.CorrectionIgnored(ctx, hbmetrics.IgnoreAtWindowEdge)
		return alignedhb.Answer{}, false
	}
	next := alignedhb.Answer{Period: cur.Period, Phase: clamped}
	p.sched = &next
	p.metrics.CorrectionApplied(ctx)
	return next, true
}

// recordClamp counts a correction that hit the window and keeps the streak
// that warns about a host clock that is off. Caller holds p.mu.
func (p *Phase) recordClamp(phase, clamped time.Duration, hit bool) {
	if !hit {
		p.clamps.Reset()
		return
	}
	p.metrics.ClampHit(context.Background())
	p.clamps.Hit(p.service, p.peer)
	p.log.Debugf("phase request %d ms clamped to %d ms, signed phase %d ms",
		phase.Milliseconds(), clamped.Milliseconds(), p.signed.Phase.Milliseconds())
}
