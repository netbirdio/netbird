// Package netrelay provides a bidirectional byte-copy helper for TCP-like
// connections with correct half-close propagation.
//
// When one direction reads EOF, the write side of the opposite connection is
// half-closed (CloseWrite) so the peer sees FIN, then the second direction is
// allowed to drain to its own EOF before both connections are fully closed.
// This preserves TCP half-close semantics (e.g. shutdown(SHUT_WR)) that the
// naive "cancel-both-on-first-EOF" pattern breaks.
package netrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DebugLogger is the minimal interface netrelay uses to surface teardown
// errors. Both *logrus.Entry and *nblog.Logger (via its Debugf method)
// satisfy it, so callers can pass whichever they already use without an
// adapter. Debugf is the only required method; callers with richer
// loggers just expose this one shape here.
type DebugLogger interface {
	Debugf(format string, args ...any)
}

// DefaultIdleTimeout is a reasonable default for Options.IdleTimeout. Callers
// that want an idle timeout but have no specific preference can use this.
const DefaultIdleTimeout = 5 * time.Minute

// halfCloser is implemented by connections that support half-close
// (e.g. *net.TCPConn, *gonet.TCPConn).
type halfCloser interface {
	CloseWrite() error
}

var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// Options configures Relay behavior. The zero value is valid: no idle timeout,
// no logging.
type Options struct {
	// IdleTimeout tears down the session if no bytes flow in either
	// direction within this window. It is a connection-wide watchdog, so a
	// long unidirectional transfer on one side keeps the other side alive.
	// Zero disables idle tracking.
	IdleTimeout time.Duration
	// Logger receives debug-level copy/idle errors. Nil suppresses logging.
	// Any logger with Debug/Debugf methods is accepted (logrus.Entry,
	// uspfilter's nblog.Logger, etc.).
	Logger DebugLogger
}

// Relay copies bytes in both directions between a and b until both directions
// EOF or ctx is canceled. On each direction's EOF it half-closes the
// opposite conn's write side (best effort) so the peer sees FIN while the
// other direction drains. Both conns are fully closed when Relay returns.
//
// a and b only need to implement io.ReadWriteCloser; connections that also
// implement CloseWrite (e.g. *net.TCPConn, ssh.Channel) get proper half-close
// propagation. Options.IdleTimeout, when set, is enforced by a connection-wide
// watchdog that tracks reads in either direction.
//
// Return values are byte counts: aToB (a.Read → b.Write) and bToA (b.Read →
// a.Write). Errors are logged via Options.Logger when set; they are not
// returned because a relay always terminates on some kind of EOF/cancel.
func Relay(ctx context.Context, a, b io.ReadWriteCloser, opts Options) (aToB, bToA int64) {
	ctx, cancel := context.WithCancel(ctx)
	closeDone := make(chan struct{})
	defer func() {
		cancel()
		<-closeDone
	}()

	go func() {
		<-ctx.Done()
		_ = a.Close()
		_ = b.Close()
		close(closeDone)
	}()

	// Both sides must support CloseWrite to propagate half-close. If either
	// doesn't, a direction's EOF can't be signaled to the peer and the other
	// direction would block forever waiting for data; in that case we fall
	// back to the cancel-both-on-first-EOF behavior.
	_, aHC := a.(halfCloser)
	_, bHC := b.(halfCloser)
	halfCloseSupported := aHC && bHC

	var (
		lastActivity atomic.Int64
		idleHit      atomic.Bool
	)
	lastActivity.Store(time.Now().UnixNano())

	if opts.IdleTimeout > 0 {
		go watchdog(ctx, cancel, &lastActivity, &idleHit, opts.IdleTimeout)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var errAToB, errBToA error

	go func() {
		defer wg.Done()
		aToB, errAToB = copyTracked(b, a, &lastActivity)
		if halfCloseSupported && isCleanEOF(errAToB) {
			halfClose(b)
		} else {
			cancel()
		}
	}()

	go func() {
		defer wg.Done()
		bToA, errBToA = copyTracked(a, b, &lastActivity)
		if halfCloseSupported && isCleanEOF(errBToA) {
			halfClose(a)
		} else {
			cancel()
		}
	}()

	wg.Wait()

	if opts.Logger != nil {
		if idleHit.Load() {
			opts.Logger.Debugf("relay closed due to idle timeout")
		}
		if errAToB != nil && !isExpectedCopyError(errAToB) {
			opts.Logger.Debugf("relay copy error (a→b): %v", errAToB)
		}
		if errBToA != nil && !isExpectedCopyError(errBToA) {
			opts.Logger.Debugf("relay copy error (b→a): %v", errBToA)
		}
	}

	return aToB, bToA
}

// watchdog enforces a connection-wide idle timeout. It cancels ctx when no
// activity has been seen on either direction for idle. It exits as soon as
// ctx is canceled so it doesn't outlive the relay.
func watchdog(ctx context.Context, cancel context.CancelFunc, lastActivity *atomic.Int64, idleHit *atomic.Bool, idle time.Duration) {
	// Cap the tick at 50ms so detection latency stays bounded regardless of
	// how large idle is, and fall back to idle/2 when that is smaller so
	// very short timeouts (mainly in tests) are still caught promptly.
	tick := min(idle/2, 50*time.Millisecond)
	if tick <= 0 {
		tick = time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			last := time.Unix(0, lastActivity.Load())
			if time.Since(last) >= idle {
				idleHit.Store(true)
				cancel()
				return
			}
		}
	}
}

// copyTracked copies from src to dst using a pooled buffer, updating
// lastActivity on every successful read so a shared watchdog can enforce a
// connection-wide idle timeout.
func copyTracked(dst io.Writer, src io.Reader, lastActivity *atomic.Int64) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)

	buf := *bufp
	var total int64
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			n, werr := checkedWrite(dst, buf[:nr])
			total += n
			if werr != nil {
				return total, werr
			}
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func checkedWrite(dst io.Writer, buf []byte) (int64, error) {
	nw, err := dst.Write(buf)
	if nw < 0 || nw > len(buf) {
		nw = 0
	}
	if err != nil {
		return int64(nw), err
	}
	if nw != len(buf) {
		return int64(nw), io.ErrShortWrite
	}
	return int64(nw), nil
}

func halfClose(conn io.ReadWriteCloser) {
	if hc, ok := conn.(halfCloser); ok {
		_ = hc.CloseWrite()
	}
}

// isCleanEOF reports whether a copy terminated on a graceful end-of-stream.
// Only in that case is it correct to propagate the EOF via CloseWrite on the
// peer; any other error means the flow is broken and both directions should
// tear down.
func isCleanEOF(err error) bool {
	return err == nil || errors.Is(err, io.EOF)
}

func isExpectedCopyError(err error) bool {
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED)
}
