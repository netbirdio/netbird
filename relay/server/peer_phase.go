package server

import (
	"time"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// alignedTransport is a connection that tunes its transport for the aligned
// heartbeat.
type alignedTransport interface {
	UseAlignedHeartbeat(period time.Duration) error
}

// healthcheckFrame returns the health check frame for the connection. On an
// aligned v2 connection it carries the phase the server sends on, so the client
// can ask for another one, and aligned is true.
func (p *Peer) healthcheckFrame() (msg []byte, aligned bool) {
	s, ok := p.phase.Schedule()
	if p.version < messages.ProtocolV2 || !ok {
		return p.enc.Healthcheck(), false
	}
	return p.enc.HealthcheckPhase(uint32(s.Phase.Milliseconds())), true
}

// hbMetrics returns the aligned heartbeat counters, nil when the peer has no
// metrics.
func (p *Peer) hbMetrics() *hbmetrics.Metrics {
	if p.metrics == nil {
		return nil
	}
	return p.metrics.AlignedHeartbeat
}

// handleHealthcheckEcho reads the phase request in a v2 health check answer. A
// new signed phase switches a stock connection to the aligned heartbeat or moves
// it to the phase of the new day. A phase alone moves the tick of an aligned
// connection. Anything invalid leaves the connection as it is.
func (p *Peer) handleHealthcheckEcho(msg []byte, hc *healthcheck.Sender) {
	if p.version < messages.ProtocolV2 {
		return
	}
	echo, err := messages.UnmarshalHealthcheckEcho(msg)
	if err != nil {
		p.log.Tracef("ignoring health check answer: %s", err)
		return
	}
	if echo.Ext.SignedPhase != nil {
		p.acceptSignedPhase(echo.Ext, hc)
	}
	if echo.HasPhase {
		p.applyPhaseRequest(time.Duration(echo.PhaseMs)*time.Millisecond, hc)
	}
}

// acceptSignedPhase moves the connection to a signed phase the client handed
// over after the handshake, once it is verified and newer than the one it has.
func (p *Peer) acceptSignedPhase(ext messages.AuthExtension, hc *healthcheck.Sender) {
	v := verifySignedPhase(ext, p.id, p.phaseVerifier, p.periodLimits, p.hbMetrics(), time.Now())
	if v == nil || !p.phase.AcceptSigned(alignedhb.Answer(v.schedule), v.day) {
		return
	}
	p.moveSchedule(v.schedule, hc)
}

// applyPhaseRequest moves the tick of an aligned connection to phase, within
// the limits of phasectl.Phase.Correct.
func (p *Peer) applyPhaseRequest(phase time.Duration, hc *healthcheck.Sender) {
	if next, ok := p.phase.Correct(phase); ok {
		p.moveSchedule(healthcheck.AlignedSchedule(next), hc)
	}
}

func (p *Peer) moveSchedule(s healthcheck.AlignedSchedule, hc *healthcheck.Sender) {
	p.tuneTransport(s.Period)
	hc.SetAligned(s)
	p.log.Debugf("aligned heartbeat moved to period %s, phase %d ms", s.Period, s.Phase.Milliseconds())
}

// tuneTransport sets the transport of an aligned connection for heartbeats every
// period. A connection keeps the stock transport until it has a verified signed
// phase, and a failed attempt is not retried for the same period.
func (p *Peer) tuneTransport(period time.Duration) {
	if period == p.transportPeriod {
		return
	}
	p.transportPeriod = period
	t, ok := p.conn.(alignedTransport)
	if !ok {
		return
	}
	if err := t.UseAlignedHeartbeat(period); err != nil {
		p.log.Debugf("transport keeps stock settings: %v", err)
	}
}
