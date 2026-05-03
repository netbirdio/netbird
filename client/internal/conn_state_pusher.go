package internal

import (
	"context"
	"sync"
	"time"

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

// Stop cancels the loop goroutine and blocks until it exits. Idempotent
// at the close-channel level (calling Stop twice panics — caller's
// responsibility to call once).
func (p *connStatePusher) Stop() {
	close(p.stop)
	p.wg.Wait()
}

// OnPeerStateChange enqueues a state-change event. Non-blocking — drops
// if the buffer is full (the next bulk tick will catch up via delta).
func (p *connStatePusher) OnPeerStateChange(ev PeerStateChangeEvent) {
	select {
	case p.events <- ev:
	default:
	}
}

// OnSnapshotRequest enqueues a snapshot-request nonce. Non-blocking,
// coalescing — multiple requests in flight result in a single full
// snapshot with the latest nonce echoed.
func (p *connStatePusher) OnSnapshotRequest(nonce uint64) {
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
	}); err != nil {
		// Push failed (mgmt reconnect, transient gRPC error, etc.).
		// Do NOT mark these events as lastPushed -- on the next tick
		// the dirty-state computation will re-include them so the
		// management server eventually catches up. Without this, a
		// peer that flipped state during a brief mgmt outage would
		// stay stale until its next state change or the 60 s heartbeat.
		return
	}
	p.mu.Lock()
	for _, ev := range events {
		p.lastPushed[ev.Pubkey] = ev
	}
	p.mu.Unlock()
}

func (p *connStatePusher) flushFull(events []PeerStateChangeEvent, inResponseToNonce uint64) {
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
	}); err != nil {
		// Same dirty-retain semantics as flushDelta. A failed full
		// snapshot leaves lastPushed unchanged so the next push (or
		// the next snapshot request) will see every peer as dirty.
		return
	}
	p.mu.Lock()
	for _, ev := range events {
		p.lastPushed[ev.Pubkey] = ev
	}
	p.mu.Unlock()
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
