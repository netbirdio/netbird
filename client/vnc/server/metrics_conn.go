//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
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
// second covers roughly one FBU round-trip at typical client request
// cadences during steady-state activity.
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

	bytesOut    atomic.Uint64
	writes      atomic.Uint64
	writeNanos  atomic.Uint64
	largestPkt  atomic.Uint64
	fbus        atomic.Uint64
	fbuBytes    atomic.Uint64
	fbuRects    atomic.Uint64
	maxFBUBytes atomic.Uint64
	maxFBURects atomic.Uint64

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

	b := m.bytesOut.Load()
	w := m.writes.Load()
	f := m.fbus.Load()
	ns := m.writeNanos.Load()

	db := b - m.tickPrevB
	dw := w - m.tickPrevW
	df := f - m.tickPrevF
	dns := ns - m.tickPrevNS
	m.tickPrevB, m.tickPrevW, m.tickPrevF, m.tickPrevNS = b, w, f, ns

	maxFBU := m.maxFBUBytes.Swap(0)
	maxRects := m.maxFBURects.Swap(0)
	maxPkt := m.largestPkt.Swap(0)

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
	ns := m.writeNanos.Load()

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

// startsFBU reports whether the Write payload begins a FramebufferUpdate
// message (message type byte 0). This holds both for the standalone 4-byte
// header that sendDirtyAndMoves writes before its rect bodies and for the
// single framed Write that sendFullUpdate / sendEmptyUpdate use to emit a
// whole FBU (header plus body) at once. Either way the FBU boundary lines
// up with this Write boundary.
func startsFBU(p []byte) bool {
	return len(p) >= 1 && p[0] == serverFramebufferUpdate
}

func (m *metricsConn) Write(p []byte) (int, error) {
	fbuStart := startsFBU(p)
	if fbuStart {
		m.flushFBUMax()
		m.fbus.Add(1)
	}

	t0 := time.Now()
	n, err := m.Conn.Write(p)
	m.writeNanos.Add(uint64(time.Since(t0).Nanoseconds()))
	m.bytesOut.Add(uint64(n))
	m.writes.Add(1)

	m.fbuBytes.Add(uint64(n))
	if fbuStart {
		// Rect count is carried in bytes 2:3 of the FBU header. A standalone
		// header records it here; the rect bodies that follow only add bytes.
		if len(p) >= 4 {
			m.fbuRects.Add(uint64(binary.BigEndian.Uint16(p[2:4])))
		}
	}

	if uint64(n) > m.largestPkt.Load() {
		m.largestPkt.Store(uint64(n))
	}
	return n, err
}

// flushFBUMax folds the bytes and rects accumulated for the FBU that just
// ended into the per-tick high-water marks, then resets the accumulators
// for the next FBU.
func (m *metricsConn) flushFBUMax() {
	if b := m.fbuBytes.Swap(0); b > m.maxFBUBytes.Load() {
		m.maxFBUBytes.Store(b)
	}
	if r := m.fbuRects.Swap(0); r > m.maxFBURects.Load() {
		m.maxFBURects.Store(r)
	}
}

func (m *metricsConn) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
		if m.recorder == nil {
			return
		}
		m.flushFBUMax()
		m.flushTick(true)
	})
	return m.Conn.Close()
}
