package hbwatch

import (
	"slices"
	"time"
)

// Level says whether a stream runs the aligned heartbeat.
type Level string

const (
	// LevelAligned: the stream gets aligned heartbeats.
	LevelAligned Level = "aligned"
	// LevelStock: the stream got no aligned heartbeat yet, for example from an
	// old server or one that cannot sign a phase.
	LevelStock Level = "stock"
)

// Result is the outcome of a phase correction, read from the phase of the next
// heartbeat of the stream.
type Result string

const (
	// ResultPending: no heartbeat since the correction was asked.
	ResultPending Result = "pending"
	// ResultApplied: the server moved its tick to the wanted phase.
	ResultApplied Result = "applied"
	// ResultClamped: the server moved its tick, but not to the wanted phase:
	// the correction hit the window around the signed phase.
	ResultClamped Result = "clamped"
	// ResultIgnored: the server kept its phase, as it does for a correction
	// that is clamped to the window edge the tick is on already.
	ResultIgnored Result = "ignored"
	// ResultUnknown: the next heartbeat came too late to tell.
	ResultUnknown Result = "unknown"
)

const (
	// BlockAfter is how many corrections in a row the server may not apply
	// before the client stops asking. The server clamps a correction to its
	// window around the signed phase, so a host clock that is off by more than
	// the window shows the same offset on every tick.
	BlockAfter = 3
	// historySize is how many corrections the status keeps.
	historySize = 16
)

// Correction is one phase correction the client asked for.
type Correction struct {
	At      time.Time
	Service Service
	Addr    string
	// Offset is how far the heartbeat landed from the Management one.
	Offset time.Duration
	// From is the phase the server sent on, Wanted the phase asked for.
	From   time.Duration
	Wanted time.Duration
	Result Result
}

// StreamStatus is the aligned heartbeat state of one stream.
type StreamStatus struct {
	Service Service
	Addr    string
	Level   Level
	// Period and Phase are those of the last heartbeat, zero before one.
	Period        time.Duration
	Phase         time.Duration
	LastHeartbeat time.Time
	// LastCorrection is nil when the stream asked for none.
	LastCorrection *Correction
	// Blocked is set when the client stopped asking for corrections after
	// BlockAfter in a row that the server did not apply.
	Blocked      bool
	BlockedInRow int
	// ClampHits counts the corrections of the service that the server did not
	// apply in full, since the client started.
	ClampHits int
}

// Snapshot is the aligned heartbeat state of all streams and the latest
// corrections, oldest first.
type Snapshot struct {
	Streams     []StreamStatus
	Corrections []Correction
}

// otherStream is a relay connection that a newer one replaced as the
// registered stream. It still sends heartbeats until it closes, and takes the
// slot back when the newer one closes first.
type otherStream struct {
	addr    string
	aligned bool
	period  time.Duration
	phase   time.Duration
	last    time.Time
	// svc, reg, id and openAt are the registration it held, to restore it.
	svc    Service
	reg    Registration
	id     uint64
	openAt time.Time
}

func (o *otherStream) status() StreamStatus {
	st := StreamStatus{Service: Relay, Addr: o.addr, Level: LevelStock}
	if o.aligned {
		st.Level = LevelAligned
		st.Period, st.Phase, st.LastHeartbeat = o.period, o.phase, o.last
	}
	return st
}

// Snapshot returns the state of the registered streams and the latest
// corrections.
func (w *Watcher) Snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	var snap Snapshot
	for _, name := range services {
		s := w.svcs[name]
		if !s.registered {
			continue
		}
		snap.Streams = append(snap.Streams, w.streamStatus(name, s))
	}
	others := make([]StreamStatus, 0, len(w.others))
	for _, o := range w.others {
		others = append(others, o.status())
	}
	slices.SortFunc(others, func(a, b StreamStatus) int {
		switch {
		case a.Addr < b.Addr:
			return -1
		case a.Addr > b.Addr:
			return 1
		default:
			return 0
		}
	})
	snap.Streams = append(snap.Streams, others...)
	for _, c := range w.history {
		snap.Corrections = append(snap.Corrections, *c)
	}
	return snap
}

// streamStatus returns the state of the registered stream of svc. Caller
// holds w.mu.
func (w *Watcher) streamStatus(svc Service, s *service) StreamStatus {
	st := StreamStatus{
		Service:      svc,
		Addr:         s.reg.Addr,
		Level:        LevelStock,
		Blocked:      s.stopped,
		BlockedInRow: s.blocked,
		ClampHits:    w.clampHits[svc],
	}
	if s.aligned {
		st.Level = LevelAligned
		st.Period, st.Phase, st.LastHeartbeat = s.period, s.phase, s.last
	}
	if s.lastCorr != nil {
		c := *s.lastCorr
		st.LastCorrection = &c
	}
	return st
}

// recordCorrection keeps c as the last correction of s and in the history.
// Caller holds w.mu.
func (w *Watcher) recordCorrection(s *service, c *Correction) {
	s.lastCorr = c
	s.pending = c
	w.history = append(w.history, c)
	if over := len(w.history) - historySize; over > 0 {
		w.history = slices.Delete(w.history, 0, over)
	}
}

// resolvePending reads the outcome of the correction asked on the last tick
// from the phase of this heartbeat. After BlockAfter corrections in a row that
// the server did not apply, the client stops asking until the stream changes.
// Caller holds w.mu.
func (w *Watcher) resolvePending(svc Service, s *service, hb Heartbeat, now time.Time, r *checkResult) {
	c := s.pending
	if c == nil {
		return
	}
	s.pending = nil
	if now.Sub(c.At) > hb.Period*3/2 {
		c.Result = ResultUnknown
		return
	}
	switch hb.Phase {
	case c.Wanted:
		c.Result = ResultApplied
		s.blocked = 0
		return
	case c.From:
		c.Result = ResultIgnored
	default:
		c.Result = ResultClamped
	}
	s.blocked++
	w.clampHits[svc]++
	r.logf("hbwatch: correction %s svc=%s wanted=%d phase=%d in_row=%d",
		c.Result, svc, c.Wanted.Milliseconds(), hb.Phase.Milliseconds(), s.blocked)
	if s.blocked < BlockAfter || s.stopped {
		return
	}
	s.stopped = true
	s.stoppedPhase = hb.Phase
	r.warnf("hbwatch: %d phase corrections in a row not applied by the %s server, stop asking. "+
		"Its clock may be off by more than the correction window", s.blocked, svc)
}

// correctionsStopped reports whether s stopped asking for corrections. A new
// phase from the server, such as the signed phase of a new day, lets it ask
// again. Caller holds w.mu.
func (s *service) correctionsStopped(phase time.Duration) bool {
	if !s.stopped {
		return false
	}
	if phase == s.stoppedPhase {
		return true
	}
	s.unblock()
	return false
}

// unblock ends a run of corrections the server did not apply.
func (s *service) unblock() {
	s.blocked = 0
	s.stopped = false
	s.stoppedPhase = 0
}

// CurrentSnapshot returns the state of the default Watcher. ok is false when
// this build has no Watcher.
func CurrentSnapshot() (snap Snapshot, ok bool) {
	if w := def(); w != nil {
		return w.Snapshot(), true
	}
	return Snapshot{}, false
}
