//go:build !js && !ios && !android

package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionTick is one sampling slice of a VNC session's wire activity.
// BytesOut / Writes / FBUs are deltas observed during this tick;
// Max* fields are the high-water marks observed during this tick (reset
// at the start of the next). Period is the wall-clock duration covered
// (typically sessionTickInterval, shorter for the final flush).
type SessionTick struct {
	Period        time.Duration
	BytesOut      uint64
	Writes        uint64
	FBUs          uint64
	MaxFBUBytes   uint64
	MaxFBURects   uint64
	MaxWriteBytes uint64
	WriteNanos    uint64
}

// sessionTickInterval is how often metricsConn emits a SessionTick. One
// second matches noVNC's request cadence so each tick covers roughly one
// FBU round-trip during steady-state activity.
const sessionTickInterval = time.Second

// metricsConn wraps a net.Conn and tracks per-session byte / write / FBU
// counters. Updates are atomic so the cost is a few atomic ops per Write
// (well under 100 ns), negligible against the syscall itself, so the wrap
// is always installed. A goroutine emits a SessionTick to the recorder
// every sessionTickInterval (only when the tick has activity to report);
// a final partial-tick flush runs on Close.
type metricsConn struct {
	net.Conn

	recorder func(SessionTick)

	bytesOut    uint64
	writes      uint64
	writeNanos  uint64
	largestPkt  uint64
	fbus        uint64
	fbuBytes    uint64
	fbuRects    uint64
	maxFBUBytes uint64
	maxFBURects uint64

	tickMu     sync.Mutex
	tickStart  time.Time
	tickPrevB  uint64
	tickPrevW  uint64
	tickPrevF  uint64
	tickPrevNS uint64

	// busyMu guards the sliding window used by BusyFraction.
	busyMu        sync.Mutex
	busyLastTime  time.Time
	busyLastNanos uint64
	busyFraction  float64

	closeOnce sync.Once
	done      chan struct{}
}

func newMetricsConn(c net.Conn, recorder func(SessionTick)) net.Conn {
	m := &metricsConn{
		Conn:      c,
		recorder:  recorder,
		tickStart: time.Now(),
		done:      make(chan struct{}),
	}
	if recorder != nil {
		go m.tickLoop()
	}
	return m
}

// tickLoop emits a SessionTick every sessionTickInterval until done.
// Empty ticks (no writes since the last tick) are skipped.
func (m *metricsConn) tickLoop() {
	t := time.NewTicker(sessionTickInterval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.flushTick(false)
		}
	}
}

// flushTick computes deltas since the last tick, resets the per-tick max
// trackers, and emits a SessionTick to the recorder. final=true forces
// emission even if no writes happened (used at session close to record
// the trailing partial period).
func (m *metricsConn) flushTick(final bool) {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()

	b := atomic.LoadUint64(&m.bytesOut)
	w := atomic.LoadUint64(&m.writes)
	f := atomic.LoadUint64(&m.fbus)
	ns := atomic.LoadUint64(&m.writeNanos)

	db := b - m.tickPrevB
	dw := w - m.tickPrevW
	df := f - m.tickPrevF
	dns := ns - m.tickPrevNS
	m.tickPrevB, m.tickPrevW, m.tickPrevF, m.tickPrevNS = b, w, f, ns

	maxFBU := atomic.SwapUint64(&m.maxFBUBytes, 0)
	maxRects := atomic.SwapUint64(&m.maxFBURects, 0)
	maxPkt := atomic.SwapUint64(&m.largestPkt, 0)

	period := time.Since(m.tickStart)
	m.tickStart = time.Now()

	if dw == 0 && !final {
		return
	}
	m.recorder(SessionTick{
		Period:        period,
		BytesOut:      db,
		Writes:        dw,
		FBUs:          df,
		MaxFBUBytes:   maxFBU,
		MaxFBURects:   maxRects,
		MaxWriteBytes: maxPkt,
		WriteNanos:    dns,
	})
}

// BusyFraction reports the fraction of recent wall time that Write spent
// blocked in the underlying socket, as an exponentially smoothed value in
// [0, 1]. Approximates downstream backpressure: persistent values near 1
// mean the socket cannot keep up with the encoder's output. Callers can
// throttle JPEG quality or skip frames in response.
func (m *metricsConn) BusyFraction() float64 {
	now := time.Now()
	ns := atomic.LoadUint64(&m.writeNanos)

	m.busyMu.Lock()
	defer m.busyMu.Unlock()
	if m.busyLastTime.IsZero() {
		m.busyLastTime = now
		m.busyLastNanos = ns
		return 0
	}
	period := now.Sub(m.busyLastTime)
	if period < 50*time.Millisecond {
		return m.busyFraction
	}
	delta := ns - m.busyLastNanos
	sample := float64(delta) / float64(period.Nanoseconds())
	if sample > 1 {
		sample = 1
	}
	const alpha = 0.4
	m.busyFraction = alpha*sample + (1-alpha)*m.busyFraction
	m.busyLastTime = now
	m.busyLastNanos = ns
	return m.busyFraction
}

// isFBUHeader reports whether the given Write payload is the 4-byte
// FramebufferUpdate header (message type 0, padding 0, rect-count high
// byte). Rect bodies are written separately by sendDirtyAndMoves, so the
// FBU/rect boundary lines up with Write boundaries.
func isFBUHeader(p []byte) bool {
	return len(p) == 4 && p[0] == serverFramebufferUpdate
}

func (m *metricsConn) Write(p []byte) (int, error) {
	if isFBUHeader(p) {
		if b := atomic.SwapUint64(&m.fbuBytes, 0); b > 0 {
			if b > atomic.LoadUint64(&m.maxFBUBytes) {
				atomic.StoreUint64(&m.maxFBUBytes, b)
			}
		}
		if r := atomic.SwapUint64(&m.fbuRects, 0); r > 0 {
			if r > atomic.LoadUint64(&m.maxFBURects) {
				atomic.StoreUint64(&m.maxFBURects, r)
			}
		}
		atomic.AddUint64(&m.fbus, 1)
	}

	t0 := time.Now()
	n, err := m.Conn.Write(p)
	atomic.AddUint64(&m.writeNanos, uint64(time.Since(t0).Nanoseconds()))
	atomic.AddUint64(&m.bytesOut, uint64(n))
	atomic.AddUint64(&m.writes, 1)
	if !isFBUHeader(p) {
		atomic.AddUint64(&m.fbuBytes, uint64(n))
		atomic.AddUint64(&m.fbuRects, 1)
	}
	if uint64(n) > atomic.LoadUint64(&m.largestPkt) {
		atomic.StoreUint64(&m.largestPkt, uint64(n))
	}
	return n, err
}

func (m *metricsConn) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
		if m.recorder == nil {
			return
		}
		if b := atomic.SwapUint64(&m.fbuBytes, 0); b > atomic.LoadUint64(&m.maxFBUBytes) {
			atomic.StoreUint64(&m.maxFBUBytes, b)
		}
		if r := atomic.SwapUint64(&m.fbuRects, 0); r > atomic.LoadUint64(&m.maxFBURects) {
			atomic.StoreUint64(&m.maxFBURects, r)
		}
		m.flushTick(true)
	})
	return m.Conn.Close()
}
