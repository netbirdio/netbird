package embed

import (
	"io"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/util/capture"
)

// CaptureOptions configures a packet capture session.
type CaptureOptions struct {
	// Output receives pcap-formatted data. Nil disables pcap output.
	Output io.Writer
	// TextOutput receives human-readable packet summaries. Nil disables text output.
	TextOutput io.Writer
	// Filter is a BPF-like filter expression (e.g. "host 10.0.0.1 and tcp port 443").
	// Empty captures all packets.
	Filter string
	// Verbose adds seq/ack, TTL, window, and total length to text output.
	Verbose bool
	// ASCII dumps transport payload as printable ASCII after each packet line.
	ASCII bool
}

// CaptureStats reports capture session counters.
type CaptureStats struct {
	Packets int64
	Bytes   int64
	Dropped int64
}

// CaptureSession represents an active packet capture. Call Stop to end the
// capture and flush buffered packets.
type CaptureSession struct {
	sess   *capture.Session
	engine *internal.Engine
}

// Stop ends the capture, flushes remaining packets, and detaches from the device.
// Safe to call multiple times.
func (cs *CaptureSession) Stop() {
	if cs.engine != nil {
		_ = cs.engine.SetCapture(nil)
		cs.engine = nil
	}
	if cs.sess != nil {
		cs.sess.Stop()
	}
}

// Stats returns current capture counters.
func (cs *CaptureSession) Stats() CaptureStats {
	s := cs.sess.Stats()
	return CaptureStats{
		Packets: s.Packets,
		Bytes:   s.Bytes,
		Dropped: s.Dropped,
	}
}

// Done returns a channel that is closed when the capture's writer goroutine
// has fully exited and all buffered packets have been flushed.
func (cs *CaptureSession) Done() <-chan struct{} {
	return cs.sess.Done()
}
