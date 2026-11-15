package server

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics"
	"github.com/netbirdio/netbird/shared/alignedhb/phasectl"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

// streamAnswer is the answer to an aligned heartbeat request. aligned is nil
// when the request had no valid signed phase: the stream then stays stock until
// the client sends one in a PhaseRequest. day is the day of the signed phase,
// set only with aligned.
type streamAnswer struct {
	period  time.Duration
	aligned *alignedhb.Answer
	day     int64
}

// streamPhase is the aligned heartbeat schedule of one Signal stream. The
// stream reader changes it on phase requests, the heartbeat loop follows it.
type streamPhase struct {
	peerID  string
	rules   *phasectl.Phase
	metrics *hbmetrics.Metrics
	// changed wakes the heartbeat loop after a schedule change.
	changed chan struct{}
}

func (a *streamAnswer) value() string {
	if a.aligned != nil {
		return a.aligned.Value()
	}
	return alignedhb.PendingAnswerValue(a.period)
}

// newStreamPhase returns the schedule of a stream with the given answer, nil
// when the client got no answer: such a stream ignores phase requests. m counts
// what the phase rules decide and may be nil.
func newStreamPhase(peerID string, answer *streamAnswer, m *hbmetrics.Metrics) *streamPhase {
	if answer == nil {
		return nil
	}
	sp := &streamPhase{
		peerID:  peerID,
		rules:   phasectl.New("signal", peerID, m, log.WithField("peer_id", peerID)),
		metrics: m,
		changed: make(chan struct{}, 1),
	}
	if a := answer.aligned; a != nil {
		sp.rules.Start(*a, answer.day)
	}
	return sp
}

// schedule returns the current schedule, ok false while the stream is stock.
func (sp *streamPhase) schedule() (alignedhb.Answer, bool) {
	return sp.rules.Schedule()
}

// handleRequest applies a phase request. A signed phase is verified and then
// switches the stream to the aligned heartbeat, or moves it to the phase of a
// new day. A phase alone moves the tick of a stream that has a verified signed
// phase. Anything invalid leaves the stream as it is.
func (sp *streamPhase) handleRequest(req *proto.PhaseRequest, verifier *phasesig.Verifier, limits alignedhb.PeriodLimits, now time.Time) {
	if sp == nil {
		return
	}
	phase := time.Duration(req.GetPhaseMillis()) * time.Millisecond
	if len(req.GetPhaseSignature()) > 0 {
		sp.acceptSigned(req, phase, verifier, limits, now)
		return
	}
	if next, ok := sp.rules.Correct(phase); ok {
		sp.move(next)
	}
}

// acceptSigned verifies a signed phase and moves the stream to it when
// phasectl.Phase.AcceptSigned takes it.
func (sp *streamPhase) acceptSigned(req *proto.PhaseRequest, phase time.Duration, verifier *phasesig.Verifier, limits alignedhb.PeriodLimits, now time.Time) {
	if verifier == nil {
		return
	}
	requested := time.Duration(req.GetPeriodSeconds()) * time.Second
	signed := alignedhb.SignedPhase{Phase: phase, Day: req.GetPhaseDay(), Signature: req.GetPhaseSignature()}
	next, err := phasectl.Verify(verifier, limits, messages.HashID(sp.peerID), requested, signed, now, sp.metrics)
	if err != nil {
		log.Debugf("ignoring signed phase from [%s]: %v", sp.peerID, err)
		return
	}
	if sp.rules.AcceptSigned(next, signed.Day) {
		sp.move(next)
	}
}

// tick allows the next correction. The heartbeat loop calls it before each
// heartbeat, so the client corrects in answer to a heartbeat it saw.
func (sp *streamPhase) tick() {
	sp.rules.Tick()
}

func (sp *streamPhase) move(next alignedhb.Answer) {
	select {
	case sp.changed <- struct{}{}:
	default:
	}
	log.Debugf("aligned heartbeat for [%s] moved to period %s, phase %d ms", sp.peerID, next.Period, next.Phase.Milliseconds())
}

// run calls send on every tick of the current schedule until ctx is done. It
// waits while the stream is stock and restarts the tick after each change,
// calling started with each schedule it starts.
func (sp *streamPhase) run(ctx context.Context, send func(alignedhb.Answer), started func(alignedhb.Answer)) {
	for {
		sched, ok := sp.schedule()
		var tick <-chan time.Time
		tickCtx, cancel := context.WithCancel(ctx)
		if ok {
			started(sched)
			tick = alignedhb.Ticker(tickCtx, sched.Period, sched.Phase, time.Now)
		}
		stop := sp.runSchedule(ctx, tick, func() {
			sp.tick()
			send(sched)
		})
		cancel()
		if stop {
			return
		}
	}
}

// runSchedule calls send on each tick until the schedule changes or ctx is
// done. It reports whether ctx is done.
func (sp *streamPhase) runSchedule(ctx context.Context, tick <-chan time.Time, send func()) (done bool) {
	for {
		select {
		case <-ctx.Done():
			return true
		case <-sp.changed:
			return false
		case <-tick:
			send()
		}
	}
}
