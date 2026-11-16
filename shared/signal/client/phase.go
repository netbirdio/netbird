package client

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

// phaseWriter writes phase requests on one Signal stream. It exists only when
// the server answered the aligned heartbeat request: an old server does not
// read the stream, and writes would fill the flow control window.
type phaseWriter struct {
	stream streamProbeSender
	sendMu *sync.Mutex
	peer   messages.PeerID
	key    string

	mu     sync.Mutex
	period time.Duration
	// sentSeq is the sequence number of the last signed phase sent on the stream.
	sentSeq uint64
}

func newPhaseWriter(stream streamProbeSender, sendMu *sync.Mutex, peer messages.PeerID, key string, period time.Duration, sentSeq uint64) *phaseWriter {
	return &phaseWriter{stream: stream, sendMu: sendMu, peer: peer, key: key, period: period, sentSeq: sentSeq}
}

// heartbeatPeriod returns the period of the stream.
func (w *phaseWriter) heartbeatPeriod() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.period
}

// correct asks the server to send its heartbeats on phase. It never blocks: the
// watcher calls it from the receive loop, inside the radio tail of the heartbeat.
func (w *phaseWriter) correct(phase time.Duration) {
	log.Infof("asking Signal for heartbeat phase %d ms", phase.Milliseconds())
	w.send(&proto.PhaseRequest{PhaseMillis: uint32(phase.Milliseconds())})
}

// forwardSignedPhases sends every new signed phase Management hands out, until
// ctx is done. A stream that opened stock switches to the aligned heartbeat this
// way, and an aligned one moves to the phase of the new day.
func (w *phaseWriter) forwardSignedPhases(ctx context.Context) {
	for {
		changed := alignedhb.SignedPhaseChanged()
		w.sendSignedPhase()
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

// sendSignedPhase sends the stored signed phase when it is newer than the one
// the stream sent.
func (w *phaseWriter) sendSignedPhase() {
	stored, ok := alignedhb.LoadStoredPhase(w.peer)
	w.mu.Lock()
	if !ok || stored.Seq <= w.sentSeq {
		w.mu.Unlock()
		return
	}
	w.sentSeq = stored.Seq
	w.period = stored.Period
	w.mu.Unlock()

	log.Infof("sending the signed heartbeat phase %d ms of day %d to Signal",
		stored.Signed.Phase.Milliseconds(), stored.Signed.Day)
	w.send(&proto.PhaseRequest{
		PhaseMillis:    uint32(stored.Signed.Phase.Milliseconds()),
		PhaseDay:       stored.Signed.Day,
		PhaseSignature: stored.Signed.Signature,
		PeriodSeconds:  alignedhb.PeriodSeconds(stored.Period),
	})
}

// send writes req on the stream in its own goroutine, since a write can block
// on flow control until the stream is cancelled.
func (w *phaseWriter) send(req *proto.PhaseRequest) {
	msg := &proto.EncryptedMessage{Key: w.key, RemoteKey: w.key, PhaseRequest: req}
	go func() {
		w.sendMu.Lock()
		defer w.sendMu.Unlock()
		if err := w.stream.Send(msg); err != nil {
			log.Debugf("failed to send phase request to Signal: %v", err)
		}
	}()
}

// serverHeartbeat returns the server heartbeat in msg, nil when msg is not one
// the server wrote. Only a server that answered the aligned heartbeat request
// sends heartbeats, and they carry no sender key. A peer can still put the
// field in a message that an old Signal server forwards, and such a frame must
// not count as a Signal heartbeat.
func (c *GrpcClient) serverHeartbeat(msg *proto.EncryptedMessage) *proto.ServerHeartbeat {
	hb := msg.GetServerHeartbeat()
	if hb == nil || msg.GetKey() != "" || c.phase.Load() == nil {
		return nil
	}
	return hb
}

// seenHeartbeat hands a Signal heartbeat to the watcher with the phase it was
// sent on. The first one on a stream that opened stock turns the answer on.
func (c *GrpcClient) seenHeartbeat(hb *proto.ServerHeartbeat) {
	pw := c.phase.Load()
	if pw == nil {
		hbwatch.Touch(hbwatch.Signal)
		return
	}
	period := pw.heartbeatPeriod()
	phase := time.Duration(hb.GetPhaseMillis()) * time.Millisecond
	if c.alignedAnswer.Load() == nil {
		log.Infof("aligned heartbeat on the Signal stream, period %s, phase %d ms", period, phase.Milliseconds())
	}
	c.setAlignedAnswer(&alignedhb.Answer{Period: period, Phase: phase})
	hbwatch.Seen(hbwatch.Signal, hbwatch.Heartbeat{Period: period, Phase: phase})
}
