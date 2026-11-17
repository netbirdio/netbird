package client

import (
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// alignedEcho builds the answers to the server health checks of one connection.
// On v2 the answer carries the phase the client wants: the server phase, or a
// correction from the heartbeat watcher. A signed phase newer than the one the
// connection sent rides along once, so a connection that opened stock or before
// the day change moves without a reconnect.
type alignedEcho struct {
	enc  messages.Encoder
	peer messages.PeerID
	log  *log.Entry

	mu     sync.Mutex
	period time.Duration
	// serverPhase is the phase of the last server health check, valid when
	// hasServerPhase is set.
	serverPhase    time.Duration
	hasServerPhase bool
	// wanted is the correction to send with the next answer, valid when
	// hasWanted is set.
	wanted    time.Duration
	hasWanted bool
	// sentSeq is the sequence number of the last signed phase sent.
	sentSeq uint64

	// frames counts the inbound frames other than health checks. The
	// heartbeat watcher reads it at its own wakes, so a relayed packet takes
	// no lock.
	frames atomic.Uint64
}

func newAlignedEcho(enc messages.Encoder, peer messages.PeerID, period time.Duration, authSeq uint64, connLog *log.Entry) *alignedEcho {
	return &alignedEcho{enc: enc, peer: peer, period: period, sentSeq: authSeq, log: connLog}
}

// frame counts one inbound frame other than a health check.
func (e *alignedEcho) frame() {
	e.frames.Add(1)
}

// frameCount returns the number of inbound frames other than health checks.
func (e *alignedEcho) frameCount() uint64 {
	return e.frames.Load()
}

func (e *alignedEcho) aligned() bool {
	return e.enc.Version() >= messages.ProtocolV2
}

// observe reads a server health check. One that carries a phase is an aligned
// heartbeat, any other one only shows the connection is alive.
func (e *alignedEcho) observe(msg []byte) {
	if !e.aligned() {
		hbwatch.TouchStream(hbwatch.Relay, e)
		return
	}
	phaseMs, ok, err := messages.UnmarshalHealthcheckPhase(msg)
	if err != nil {
		e.log.Debugf("invalid health check payload: %s", err)
	}
	e.mu.Lock()
	e.hasServerPhase = err == nil && ok
	e.serverPhase = time.Duration(phaseMs) * time.Millisecond
	period, phase, has := e.period, e.serverPhase, e.hasServerPhase
	e.mu.Unlock()
	// The watcher must not follow a schedule outside the client limits, whatever
	// the server sends.
	clamped, _ := alignedhb.ClampAnswer(alignedhb.Answer{Period: period, Phase: phase})
	period, phase = clamped.Period, clamped.Phase
	if !has {
		hbwatch.TouchStream(hbwatch.Relay, e)
		return
	}
	hbwatch.Seen(hbwatch.Relay, hbwatch.Heartbeat{Period: period, Phase: phase, Stream: e})
}

// correct queues phase for the next answer. The watcher calls it from observe,
// so the correction goes out with the answer to the same heartbeat.
func (e *alignedEcho) correct(phase time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wanted, e.hasWanted = phase, true
}

// answer returns the answer to the last server health check.
func (e *alignedEcho) answer() []byte {
	if !e.aligned() {
		return e.enc.Healthcheck()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if msg, ok := e.signedAnswer(); ok {
		return msg
	}
	if e.hasWanted {
		e.hasWanted = false
		e.log.Infof("asking the relay server for heartbeat phase %d ms", e.wanted.Milliseconds())
		return e.enc.HealthcheckEcho(uint32(e.wanted.Milliseconds()), nil)
	}
	if e.hasServerPhase {
		return e.enc.HealthcheckEcho(uint32(e.serverPhase.Milliseconds()), nil)
	}
	return e.enc.Healthcheck()
}

// signedAnswer returns an answer with the stored signed phase when it is newer
// than the one this connection sent. The signed phase replaces any pending
// correction, which was measured against the old phase. Caller holds e.mu.
func (e *alignedEcho) signedAnswer() ([]byte, bool) {
	stored, ok := alignedhb.LoadStoredPhase(e.peer)
	if !ok || stored.Seq <= e.sentSeq {
		return nil, false
	}
	ext, period, err := signedPhaseExtension(stored)
	if err != nil {
		e.log.Warnf("failed to encode the signed heartbeat phase: %s", err)
		return nil, false
	}
	e.sentSeq = stored.Seq
	e.period = period
	e.hasWanted = false
	e.log.Infof("sending the signed heartbeat phase %d ms of day %d to the relay server",
		stored.Signed.Phase.Milliseconds(), stored.Signed.Day)
	return e.enc.HealthcheckEcho(uint32(stored.Signed.Phase.Milliseconds()), ext), true
}
