package capture

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const defaultBufSize = 256

type packetEntry struct {
	ts   time.Time
	data []byte
	dir  Direction
}

// Session manages an active packet capture. Packets are offered via Offer,
// buffered in a channel, and written to configured sinks by a background
// goroutine. This keeps the hot path (FilteredDevice.Read/Write) non-blocking.
//
// The caller must call Stop when done to flush remaining packets and release
// resources.
type Session struct {
	pcapW   *PcapWriter
	textW   *TextWriter
	matcher Matcher
	snapLen uint32
	flushFn func()

	ch      chan packetEntry
	done    chan struct{}
	stopped chan struct{}

	closeOnce sync.Once
	closed    atomic.Bool
	packets   atomic.Int64
	bytes     atomic.Int64
	dropped   atomic.Int64
	started   time.Time
}

// NewSession creates and starts a capture session. At least one of
// Options.Output or Options.TextOutput must be non-nil.
func NewSession(opts Options) (*Session, error) {
	if opts.Output == nil && opts.TextOutput == nil {
		return nil, fmt.Errorf("at least one output sink required")
	}

	snapLen := opts.SnapLen
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}

	bufSize := opts.BufSize
	if bufSize <= 0 {
		bufSize = defaultBufSize
	}

	s := &Session{
		matcher: opts.Matcher,
		snapLen: snapLen,
		ch:      make(chan packetEntry, bufSize),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
		started: time.Now(),
	}

	if opts.Output != nil {
		s.pcapW = NewPcapWriter(opts.Output, snapLen)
	}
	if opts.TextOutput != nil {
		s.textW = NewTextWriter(opts.TextOutput, opts.Verbose, opts.ASCII)
	}

	s.flushFn = buildFlushFn(opts.Output, opts.TextOutput)

	go s.run()
	return s, nil
}

// Offer submits a packet for capture. It returns immediately and never blocks
// the caller. If the internal buffer is full the packet is dropped silently.
//
// outbound should be true for packets leaving the host (FilteredDevice.Read
// path) and false for packets arriving (FilteredDevice.Write path).
//
// Offer satisfies the device.PacketCapture interface.
func (s *Session) Offer(data []byte, outbound bool) {
	if s.closed.Load() {
		return
	}

	if s.matcher != nil && !s.matcher.Match(data) {
		return
	}

	captureLen := len(data)
	if s.snapLen > 0 && uint32(captureLen) > s.snapLen {
		captureLen = int(s.snapLen)
	}

	copied := make([]byte, captureLen)
	copy(copied, data)

	dir := Inbound
	if outbound {
		dir = Outbound
	}

	select {
	case s.ch <- packetEntry{ts: time.Now(), data: copied, dir: dir}:
		s.packets.Add(1)
		s.bytes.Add(int64(len(data)))
	default:
		s.dropped.Add(1)
	}
}

// Stop signals the session to stop accepting packets, drains any buffered
// packets to the sinks, and waits for the writer goroutine to exit.
// It is safe to call multiple times.
func (s *Session) Stop() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
	})
	<-s.stopped
}

// Done returns a channel that is closed when the session's writer goroutine
// has fully exited and all buffered packets have been flushed.
func (s *Session) Done() <-chan struct{} {
	return s.stopped
}

// Stats returns current capture counters.
func (s *Session) Stats() Stats {
	return Stats{
		Packets: s.packets.Load(),
		Bytes:   s.bytes.Load(),
		Dropped: s.dropped.Load(),
	}
}

func (s *Session) run() {
	defer close(s.stopped)

	for {
		select {
		case pkt := <-s.ch:
			s.write(pkt)
		case <-s.done:
			s.drain()
			return
		}
	}
}

func (s *Session) drain() {
	for {
		select {
		case pkt := <-s.ch:
			s.write(pkt)
		default:
			return
		}
	}
}

func (s *Session) write(pkt packetEntry) {
	if s.pcapW != nil {
		// Best-effort: if the writer fails (broken pipe etc.), discard silently.
		_ = s.pcapW.WritePacket(pkt.ts, pkt.data)
	}
	if s.textW != nil {
		_ = s.textW.WritePacket(pkt.ts, pkt.data, pkt.dir)
	}
	s.flushFn()
}

// buildFlushFn returns a function that flushes all writers that support it.
// This covers http.Flusher and similar streaming writers.
func buildFlushFn(writers ...any) func() {
	type flusher interface {
		Flush()
	}

	var fns []func()
	for _, w := range writers {
		if w == nil {
			continue
		}
		if f, ok := w.(flusher); ok {
			fns = append(fns, f.Flush)
		}
	}

	switch len(fns) {
	case 0:
		return func() {
			// no writers to flush
		}
	case 1:
		return fns[0]
	default:
		return func() {
			for _, fn := range fns {
				fn()
			}
		}
	}
}
