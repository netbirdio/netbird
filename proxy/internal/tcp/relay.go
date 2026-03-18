package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/netutil"
)

// errIdleTimeout is returned when a relay connection is closed due to inactivity.
var errIdleTimeout = errors.New("idle timeout")

// DefaultIdleTimeout is the default idle timeout for TCP relay connections.
// A zero value disables idle timeout checking.
const DefaultIdleTimeout = 5 * time.Minute

// halfCloser is implemented by connections that support half-close
// (e.g. *net.TCPConn). When one copy direction finishes, we signal
// EOF to the remote by closing the write side while keeping the read
// side open so the other direction can drain.
type halfCloser interface {
	CloseWrite() error
}

// copyBufPool avoids allocating a new 32KB buffer per io.Copy call.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// Relay copies data bidirectionally between src and dst until both
// sides are done or the context is canceled. When idleTimeout is
// non-zero, each direction's read is deadline-guarded; if no data
// flows within the timeout the connection is torn down. When one
// direction finishes, it half-closes the write side of the
// destination (if supported) to signal EOF, allowing the other
// direction to drain gracefully before the full connection teardown.
func Relay(ctx context.Context, logger *log.Entry, src, dst net.Conn, idleTimeout time.Duration) (srcToDst, dstToSrc int64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = src.Close()
		_ = dst.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var errSrcToDst, errDstToSrc error

	go func() {
		defer wg.Done()
		srcToDst, errSrcToDst = copyWithIdleTimeout(dst, src, idleTimeout)
		halfClose(dst)
		cancel()
	}()

	go func() {
		defer wg.Done()
		dstToSrc, errDstToSrc = copyWithIdleTimeout(src, dst, idleTimeout)
		halfClose(src)
		cancel()
	}()

	wg.Wait()

	if errors.Is(errSrcToDst, errIdleTimeout) || errors.Is(errDstToSrc, errIdleTimeout) {
		logger.Debug("relay closed due to idle timeout")
	}
	if errSrcToDst != nil && !isExpectedCopyError(errSrcToDst) {
		logger.Debugf("relay copy error (src→dst): %v", errSrcToDst)
	}
	if errDstToSrc != nil && !isExpectedCopyError(errDstToSrc) {
		logger.Debugf("relay copy error (dst→src): %v", errDstToSrc)
	}

	return srcToDst, dstToSrc
}

// copyWithIdleTimeout copies from src to dst using a pooled buffer.
// When idleTimeout > 0 it sets a read deadline on src before each
// read and treats a timeout as an idle-triggered close.
func copyWithIdleTimeout(dst io.Writer, src io.Reader, idleTimeout time.Duration) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)

	if idleTimeout <= 0 {
		return io.CopyBuffer(dst, src, *bufp)
	}

	conn, ok := src.(net.Conn)
	if !ok {
		return io.CopyBuffer(dst, src, *bufp)
	}

	buf := *bufp
	var total int64
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return total, err
		}
		nr, readErr := src.Read(buf)
		if nr > 0 {
			n, err := checkedWrite(dst, buf[:nr])
			total += n
			if err != nil {
				return total, err
			}
		}
		if readErr != nil {
			if netutil.IsTimeout(readErr) {
				return total, errIdleTimeout
			}
			return total, readErr
		}
	}
}

// checkedWrite writes buf to dst and returns the number of bytes written.
// It guards against short writes and negative counts per io.Copy convention.
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

func isExpectedCopyError(err error) bool {
	return errors.Is(err, errIdleTimeout) || netutil.IsExpectedError(err)
}

// halfClose attempts to half-close the write side of the connection.
// If the connection does not support half-close, this is a no-op.
func halfClose(conn net.Conn) {
	if hc, ok := conn.(halfCloser); ok {
		// Best-effort; the full close will follow shortly.
		_ = hc.CloseWrite()
	}
}
