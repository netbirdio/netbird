package bodytap

import (
	"bytes"
	"net/http"
	"sync"

	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
)

// CapturingResponseWriter wraps an http.ResponseWriter, forwards bytes
// immediately to the client, and tees a bounded copy into an internal
// buffer for middleware inspection. Streaming-aware in the sense that
// every byte the upstream emits flows to the client without queuing
// — the tee just sees a bounded prefix. SSE-aware parsing happens in
// the response middleware against the buffered prefix; this writer
// makes no attempt to demux event boundaries.
//
// Flusher and Hijacker are preserved via responsewriter.PassthroughWriter.
type CapturingResponseWriter struct {
	*responsewriter.PassthroughWriter
	mu          sync.Mutex
	buf         bytes.Buffer
	cap         int64
	status      int
	statusSet   bool
	written     int64
	truncated   bool
	stopped     bool
	releaseBuf  func()
	released    sync.Once
	bypassed    bool
	bypassReas  string
	acquiredCap int64
}

// NewCapturingResponseWriter returns a writer that tees up to maxBytes
// into a capped buffer while forwarding bytes to the underlying writer
// immediately. When budget is non-nil the writer pre-acquires maxBytes
// from it and the returned wrapper must be released by calling
// Release() once the response is fully forwarded. If the budget cannot
// be acquired the writer falls back to forwarding the response
// unmodified, exposes Bypassed()=true with reason BypassBudget, and
// releases nothing.
func NewCapturingResponseWriter(w http.ResponseWriter, maxBytes int64, b Budget) *CapturingResponseWriter {
	cw := &CapturingResponseWriter{
		PassthroughWriter: responsewriter.New(w),
		cap:               maxBytes,
		status:            http.StatusOK,
		releaseBuf:        func() {},
	}
	if maxBytes <= 0 {
		// Capture disabled: mark stopped so Write never tees and never
		// flags truncation (a zero cap means "don't capture", not
		// "captured nothing").
		cw.stopped = true
		return cw
	}
	if b == nil {
		return cw
	}
	if !b.Acquire(maxBytes) {
		cw.bypassed = true
		cw.bypassReas = BypassBudget
		cw.cap = 0
		cw.stopped = true
		return cw
	}
	cw.acquiredCap = maxBytes
	cw.releaseBuf = func() { b.Release(maxBytes) }
	return cw
}

// Release returns the response capture budget acquired at construction
// back to the shared pool. Idempotent. Safe to call from a defer
// immediately after construction even when the writer ended up
// bypassing the budget.
func (c *CapturingResponseWriter) Release() {
	if c == nil {
		return
	}
	c.released.Do(func() {
		if c.releaseBuf != nil {
			c.releaseBuf()
		}
	})
}

// Bypassed reports whether the writer fell through to a no-tee
// passthrough because the response capture budget could not be
// acquired.
func (c *CapturingResponseWriter) Bypassed() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bypassed
}

// BypassReason returns the bypass code recorded by the budget check.
// Empty when capture proceeded normally.
func (c *CapturingResponseWriter) BypassReason() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bypassReas
}

// WriteHeader records the status code and forwards it to the underlying
// writer. Only the first call commits the status — matching HTTP semantics,
// where superfluous WriteHeader calls (and any call after the body has
// started) are ignored — so Status() reflects the code actually sent.
func (c *CapturingResponseWriter) WriteHeader(status int) {
	c.mu.Lock()
	if c.statusSet {
		c.mu.Unlock()
		return
	}
	c.status = status
	c.statusSet = true
	c.mu.Unlock()
	c.PassthroughWriter.WriteHeader(status)
}

// Write forwards p to the underlying writer unmodified and copies up
// to the remaining buffer capacity into the tee buffer.
func (c *CapturingResponseWriter) Write(p []byte) (int, error) {
	n, err := c.PassthroughWriter.Write(p)
	if n > 0 {
		c.mu.Lock()
		// The first byte commits the status (implicit 200 if WriteHeader was
		// never called); a later WriteHeader must not change Status().
		c.statusSet = true
		c.written += int64(n)
		if !c.stopped {
			remaining := c.cap - int64(c.buf.Len())
			if remaining <= 0 {
				c.truncated = true
				c.stopped = true
			} else {
				take := int64(n)
				if take > remaining {
					take = remaining
					c.truncated = true
					c.stopped = true
				}
				c.buf.Write(p[:take])
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// Status returns the captured status code (defaults to 200 when
// WriteHeader has not been called).
func (c *CapturingResponseWriter) Status() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Body returns a copy of the buffered response prefix.
func (c *CapturingResponseWriter) Body() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.buf.Len())
	copy(out, c.buf.Bytes())
	return out
}

// Truncated reports whether the buffered prefix stopped short of the
// full response stream.
func (c *CapturingResponseWriter) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// BytesWritten returns the total number of bytes forwarded to the
// underlying writer.
func (c *CapturingResponseWriter) BytesWritten() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}
