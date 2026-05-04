package internal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// PeerStateChangeEvent is the per-peer connection-state snapshot the
// pusher receives from the engine. Phase 3.7i of #5989.
type PeerStateChangeEvent struct {
	Pubkey        string
	ConnType      mgmProto.ConnType
	LastHandshake time.Time
	LatencyMS     uint32
	Endpoint      string
	RelayServer   string
	RxBytes       uint64
	TxBytes       uint64
}

// PushSink is the upstream Sync mgmt-client interface the pusher writes
// to. The Engine's mgmClient.SyncPeerConnections satisfies it.
type PushSink interface {
	Push(ctx context.Context, m *mgmProto.PeerConnectionMap) error
}

// PeerStateSource produces the current full snapshot of per-peer state
// when the pusher needs to compute a delta or build a full snapshot.
// The Engine's statusRecorder snapshot satisfies it.
type PeerStateSource interface {
	SnapshotAllRemotePeers() []PeerStateChangeEvent
}

type pusherTuning struct {
	baseInterval time.Duration
	maxInterval  time.Duration
	doubleAfter  int
}

var defaultTuning = pusherTuning{
	baseInterval: 60 * time.Second,
	maxInterval:  300 * time.Second,
	doubleAfter:  3,
}

type connStatePusher struct {
	sink   PushSink
	source PeerStateSource
	tuning pusherTuning

	// sessionID is generated once per process; mgmt uses it to detect a
	// daemon restart even if a stale unary RPC from the previous process
	// arrives AFTER the new process's full snapshot. Codex follow-up to
	// PR review of Phase 3.7i.
	sessionID uint64

	// disabled is set true once the management server has rejected the
	// SyncPeerConnections RPC with codes.Unimplemented. Old mgmt servers
	// don't ship the new RPC at all; without this latch the pusher would
	// keep retrying every heartbeat (60 s) and on every state change,
	// burning wakeups and gRPC retries against a server that will never
	// accept the call. Detected on the first push, then no further pushes
	// are attempted for the lifetime of this pusher (i.e. until the next
	// daemon restart, which gets a fresh detection cycle). Codex review
	// of Phase 3.7i.
	disabled atomic.Bool

	mu         sync.Mutex
	lastPushed map[string]PeerStateChangeEvent
	seq        uint64

	events       chan PeerStateChangeEvent
	snapshotReq  chan uint64
	initialReady chan struct{} // closed by TriggerInitialSnapshot
	stop         chan struct{}
	wg           sync.WaitGroup
}

func newConnStatePusher(sink PushSink, source PeerStateSource) *connStatePusher {
	return newConnStatePusherForTest(sink, source, defaultTuning)
}

func newConnStatePusherForTest(sink PushSink, source PeerStateSource, t pusherTuning) *connStatePusher {
	p := &connStatePusher{
		sink:        sink,
		source:      source,
		tuning:      t,
		sessionID:   newSessionID(),
		lastPushed:   make(map[string]PeerStateChangeEvent),
		events:       make(chan PeerStateChangeEvent, 64),
		snapshotReq:  make(chan uint64, 4),
		initialReady: make(chan struct{}),
		stop:         make(chan struct{}),
	}
	p.wg.Add(1)
	go p.loop()
	return p
}

// newSessionID returns a random non-zero uint64. Zero is reserved as
// the "legacy / unset" sentinel mgmt falls back to seq-only behaviour
// for, so we re-roll on the (cryptographically negligible) chance of
// drawing it.
func newSessionID() uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		if id := binary.BigEndian.Uint64(b[:]); id != 0 {
			return id
		}
	}
}

// Stop cancels the loop goroutine and blocks until it exits. Idempotent
// at the close-channel level (calling Stop twice panics — caller's
// responsibility to call once).
func (p *connStatePusher) Stop() {
	close(p.stop)
	p.wg.Wait()
}

// OnPeerStateChange enqueues a state-change event. Non-blocking — drops
// if the buffer is full (the next bulk tick will catch up via delta).
//
// Safe on a nil receiver: Engine.Stop nils e.connStatePusher before
// removeAllPeers runs, but the status-recorder listener registered in
// Engine.Start is still wired and may fire a few more events during
// peer cleanup. A nil-receiver no-op makes the cleanup path cheap and
// avoids a panic on the engine shutdown race.
func (p *connStatePusher) OnPeerStateChange(ev PeerStateChangeEvent) {
	if p == nil {
		return
	}
	select {
	case p.events <- ev:
	default:
	}
}

// OnSnapshotRequest enqueues a snapshot-request nonce. Non-blocking,
// coalescing — multiple requests in flight result in a single full
// snapshot with the latest nonce echoed. Nil-receiver safe for the
// same shutdown-race reason as OnPeerStateChange.
func (p *connStatePusher) OnSnapshotRequest(nonce uint64) {
	if p == nil {
		return
	}
	select {
	case p.snapshotReq <- nonce:
	default:
	}
}

// TriggerInitialSnapshot signals the loop that the engine has populated
// the peer-state source for the first time and the loop may now send
// its initial full snapshot to management. Idempotent — subsequent
// calls are no-ops.
//
// Without this, newConnStatePusher's loop would race with the engine's
// peer-population path: starting in engine.Start (before addNewPeers
// has run for the first NetworkMap), it would emit an empty snapshot,
// and management would not see real peers until either a state change
// or the 60 s heartbeat tick.
func (p *connStatePusher) TriggerInitialSnapshot() {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.initialReady:
		// already triggered
	default:
		close(p.initialReady)
	}
}

func (p *connStatePusher) loop() {
	defer p.wg.Done()
	// Wait until the engine signals that the first NetworkMap has been
	// applied (peers populated). Sending an initial full snapshot before
	// peers exist would publish an empty map to management, which would
	// only get repaired on the next per-peer state change or after the
	// 60 s heartbeat. Bail out cleanly if Stop is called first.
	select {
	case <-p.initialReady:
	case <-p.stop:
		return
	}
	if p.source != nil {
		// Codex#4: drain any per-peer events that landed in p.events
		// BEFORE initialReady fired. Those events reflect state that
		// the upcoming flushFull (which calls SnapshotAllRemotePeers)
		// will already cover; replaying them as later deltas would
		// make the management server see them out of order (an old
		// delta arriving AFTER a snapshot at higher seq).
		// Only drain when we ARE going to send a snapshot — otherwise
		// pre-init events are still valid state changes that need to
		// flow through the normal delta path.
	drainLoop:
		for {
			select {
			case <-p.events:
				// discard
			default:
				break drainLoop
			}
		}
		p.flushFull(p.source.SnapshotAllRemotePeers(), 0)
	}
	interval := p.tuning.baseInterval
	emptyTicks := 0
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-p.stop:
			return
		case ev := <-p.events:
			batch := []PeerStateChangeEvent{ev}
			drain := true
			for drain {
				select {
				case e2 := <-p.events:
					batch = append(batch, e2)
				default:
					drain = false
				}
			}
			p.flushDelta(batch)
			interval = p.tuning.baseInterval
			emptyTicks = 0
			timer.Reset(interval)
		case nonce := <-p.snapshotReq:
			if p.source != nil {
				p.flushFull(p.source.SnapshotAllRemotePeers(), nonce)
			}
			interval = p.tuning.baseInterval
			emptyTicks = 0
			timer.Reset(interval)
		case <-timer.C:
			delta := p.computeDeltaFromSource()
			if len(delta) > 0 {
				p.flushDelta(delta)
				interval = p.tuning.baseInterval
				emptyTicks = 0
			} else {
				emptyTicks++
				if emptyTicks >= p.tuning.doubleAfter && interval < p.tuning.maxInterval {
					interval *= 2
					if interval > p.tuning.maxInterval {
						interval = p.tuning.maxInterval
					}
					emptyTicks = 0
				}
			}
			timer.Reset(interval)
		}
	}
}

func (p *connStatePusher) flushDelta(events []PeerStateChangeEvent) {
	if len(events) == 0 {
		return
	}
	if p.disabled.Load() {
		// Mgmt server is pre-3.7i and rejected SyncPeerConnections with
		// Unimplemented earlier in this session. Mark events as pushed so
		// the dirty-state computation doesn't keep re-flagging them and
		// retrying every tick.
		p.markPushed(events)
		return
	}
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.mu.Unlock()
	entries := make([]*mgmProto.PeerConnectionEntry, 0, len(events))
	for _, ev := range events {
		entries = append(entries, eventToEntry(ev))
	}
	if err := p.sink.Push(context.Background(), &mgmProto.PeerConnectionMap{
		Seq:          seq,
		FullSnapshot: false,
		Entries:      entries,
		SessionId:    p.sessionID,
	}); err != nil {
		if p.handleUnimplemented(err) {
			// Old server: mark these as pushed so we don't keep retrying.
			p.markPushed(events)
			return
		}
		// Push failed (mgmt reconnect, transient gRPC error, etc.).
		// Do NOT mark these events as lastPushed -- on the next tick
		// the dirty-state computation will re-include them so the
		// management server eventually catches up. Without this, a
		// peer that flipped state during a brief mgmt outage would
		// stay stale until its next state change or the 60 s heartbeat.
		return
	}
	p.markPushed(events)
}

// markPushed records the events as the latest known mgmt-side state.
// Pulled out so the disabled and success paths share the same locking.
func (p *connStatePusher) markPushed(events []PeerStateChangeEvent) {
	p.mu.Lock()
	for _, ev := range events {
		p.lastPushed[ev.Pubkey] = ev
	}
	p.mu.Unlock()
}

// handleUnimplemented inspects an error from the sink and, if it looks
// like the mgmt server doesn't implement SyncPeerConnections, latches
// the pusher into the disabled state and logs once. Returns true if the
// error was Unimplemented (caller should treat as "don't retry"); false
// otherwise (caller should keep dirty so the next tick retries).
func (p *connStatePusher) handleUnimplemented(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unimplemented {
		return false
	}
	// CompareAndSwap so the log line and the warn-once message only fire
	// the first time we hit Unimplemented in this pusher's lifetime.
	if p.disabled.CompareAndSwap(false, true) {
		log.Warnf("management server does not implement SyncPeerConnections (Phase 3.7i feature); peer-connection-state push disabled for this session — peer state UI on other clients may be less detailed but the daemon is unaffected")
	}
	return true
}

func (p *connStatePusher) flushFull(events []PeerStateChangeEvent, inResponseToNonce uint64) {
	if p.disabled.Load() {
		// Mgmt is pre-3.7i; mark seen so we don't retry on every snapshot
		// request. The mgmt-side store will not have any of our entries,
		// but other clients' UIs will fall back to their pre-3.7i
		// heuristics for our peer (legacy ConnStatus path on PeerState).
		p.markPushed(events)
		return
	}
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.mu.Unlock()
	entries := make([]*mgmProto.PeerConnectionEntry, 0, len(events))
	for _, ev := range events {
		entries = append(entries, eventToEntry(ev))
	}
	if err := p.sink.Push(context.Background(), &mgmProto.PeerConnectionMap{
		Seq:               seq,
		FullSnapshot:      true,
		Entries:           entries,
		InResponseToNonce: inResponseToNonce,
		SessionId:         p.sessionID,
	}); err != nil {
		if p.handleUnimplemented(err) {
			p.markPushed(events)
			return
		}
		// Same dirty-retain semantics as flushDelta. A failed full
		// snapshot leaves lastPushed unchanged so the next push (or
		// the next snapshot request) will see every peer as dirty.
		return
	}
	p.markPushed(events)
}

func (p *connStatePusher) computeDeltaFromSource() []PeerStateChangeEvent {
	if p.source == nil {
		return nil
	}
	all := p.source.SnapshotAllRemotePeers()
	p.mu.Lock()
	defer p.mu.Unlock()
	delta := make([]PeerStateChangeEvent, 0, len(all))
	for _, ev := range all {
		prev, had := p.lastPushed[ev.Pubkey]
		if !had || isMaterialChange(prev, ev) {
			delta = append(delta, ev)
		}
	}
	return delta
}

// isMaterialChange decides whether ev's delta vs prev should generate a
// push. Always include conn_type/endpoint flips. Latency: include if
// |delta| >= 5 ms OR the handshake is newer (so any peer that's been
// actively talking AT ALL since the last push is reported, even if
// latency is stable). Phase 3.7i (rev 4 — was AND in rev 3, too
// conservative).
func isMaterialChange(prev, cur PeerStateChangeEvent) bool {
	if prev.ConnType != cur.ConnType {
		return true
	}
	if prev.Endpoint != cur.Endpoint {
		return true
	}
	// Codex review: relay-server flips MUST surface immediately. The
	// daemon does ship this field in eventToEntry; without including
	// it here we'd only push it on a parallel material change, leaving
	// dashboards stuck on the old relay-server URL whenever a peer
	// migrates between relays.
	if prev.RelayServer != cur.RelayServer {
		return true
	}
	const latencyThresholdMS = 5
	d := int32(cur.LatencyMS) - int32(prev.LatencyMS)
	if d < 0 {
		d = -d
	}
	if d >= latencyThresholdMS {
		return true
	}
	if cur.LastHandshake.After(prev.LastHandshake) {
		return true
	}
	return false
}

func eventToEntry(ev PeerStateChangeEvent) *mgmProto.PeerConnectionEntry {
	e := &mgmProto.PeerConnectionEntry{
		RemotePubkey: ev.Pubkey,
		ConnType:     ev.ConnType,
		LatencyMs:    ev.LatencyMS,
		Endpoint:     ev.Endpoint,
		RelayServer:  ev.RelayServer,
		RxBytes:      ev.RxBytes,
		TxBytes:      ev.TxBytes,
	}
	if !ev.LastHandshake.IsZero() {
		e.LastHandshake = timestamppb.New(ev.LastHandshake)
	}
	return e
}
