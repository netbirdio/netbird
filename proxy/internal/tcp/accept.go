package tcp

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// gvisorInvalidEndpointMsg is the canonical text gVisor netstack returns
// when Accept() is called on a listener whose underlying endpoint has
// been destroyed (peer rekey, embedded-client reset, account churn).
// There is no exported sentinel from gvisor.dev/gvisor/pkg/tcpip that
// survives gonet's *net.OpError wrapping in a way errors.Is can match,
// so we fall back to a string check. Stable across the gVisor versions
// netbird pins.
const gvisorInvalidEndpointMsg = "endpoint is in invalid state"

// IsClosedListenerErr reports whether err signals that an accept loop
// should exit because the underlying listener can no longer serve
// connections. It recognises:
//
//   - net.ErrClosed for stdlib listeners (Listener.Close was called).
//   - gVisor's "endpoint is in invalid state" for netstack-backed
//     listeners whose endpoint was destroyed out from under them
//     (typically when a per-account WireGuard netstack is reset without
//     also tearing the listener entry down).
//
// Without the gVisor branch an accept loop on a netstack listener spins
// CPU-hot forever after the endpoint dies, because Accept never blocks
// again and the error neither matches net.ErrClosed nor cancels ctx.
func IsClosedListenerErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), gvisorInvalidEndpointMsg)
}

// AcceptBackoff implements the exponential backoff used by
// net/http.Server.Serve for transient Accept errors. Without it a loop
// hitting a sticky unknown error burns a full CPU core. The zero value
// is ready to use; call Reset after a successful Accept.
type AcceptBackoff struct {
	delay time.Duration
}

// minAcceptDelay / maxAcceptDelay mirror the stdlib defaults
// (net/http.Server.Serve) and keep us well below 1 log line per second
// per orphaned listener.
const (
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second
)

// Backoff waits the next exponential delay (5ms doubling up to 1s) and
// returns true when the wait completed. Returns false if ctx fired
// during the wait — callers should treat that as "exit the loop".
func (b *AcceptBackoff) Backoff(ctx context.Context) bool {
	b.advance()
	select {
	case <-ctx.Done():
		return false
	case <-time.After(b.delay):
		return true
	}
}

// Reset clears the accumulated delay so the next failure starts at the
// minimum delay again. Call after a successful Accept.
func (b *AcceptBackoff) Reset() { b.delay = 0 }

func (b *AcceptBackoff) advance() {
	if b.delay == 0 {
		b.delay = minAcceptDelay
	} else {
		b.delay *= 2
	}
	if b.delay > maxAcceptDelay {
		b.delay = maxAcceptDelay
	}
}
