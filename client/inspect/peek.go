package inspect

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

// peekConn wraps a net.Conn with a buffer that allows reading ahead
// without consuming data. Subsequent Read calls return the buffered
// bytes first, then read from the underlying connection.
type peekConn struct {
	net.Conn
	buf bytes.Buffer
	// peeked holds the raw bytes that were peeked, available for replay.
	peeked []byte
}

// newPeekConn wraps conn for peek-ahead reading.
func newPeekConn(conn net.Conn) *peekConn {
	return &peekConn{Conn: conn}
}

// Peek reads exactly n bytes from the connection without consuming them.
// The peeked bytes are replayed on subsequent Read calls.
// Peek may only be called once; calling it again returns an error.
func (c *peekConn) Peek(n int) ([]byte, error) {
	if c.peeked != nil {
		return nil, fmt.Errorf("peek already called")
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, fmt.Errorf("peek %d bytes: %w", n, err)
	}

	c.peeked = buf
	c.buf.Write(buf)

	return buf, nil
}

// PeekAll reads up to n bytes, returning whatever is available.
// Unlike Peek, it does not require exactly n bytes.
func (c *peekConn) PeekAll(n int) ([]byte, error) {
	if c.peeked != nil {
		return nil, fmt.Errorf("peek already called")
	}

	buf := make([]byte, n)
	nr, err := c.Conn.Read(buf)
	if nr > 0 {
		c.peeked = buf[:nr]
		c.buf.Write(c.peeked)
	}
	if err != nil && nr == 0 {
		return nil, fmt.Errorf("peek: %w", err)
	}

	return c.peeked, nil
}

// PeekMore extends the peeked buffer to at least n total bytes.
// The buffer is reset and refilled with the extended data.
// The returned slice is the internal peeked buffer; callers must not
// retain references from prior Peek/PeekMore calls after calling this.
func (c *peekConn) PeekMore(n int) ([]byte, error) {
	if len(c.peeked) >= n {
		return c.peeked[:n], nil
	}

	remaining := n - len(c.peeked)
	extra := make([]byte, remaining)
	if _, err := io.ReadFull(c.Conn, extra); err != nil {
		return nil, fmt.Errorf("peek more %d bytes: %w", remaining, err)
	}

	// Pre-allocate to avoid reallocation detaching previously returned slices.
	combined := make([]byte, 0, n)
	combined = append(combined, c.peeked...)
	combined = append(combined, extra...)
	c.peeked = combined
	c.buf.Reset()
	c.buf.Write(c.peeked)

	return c.peeked, nil
}

// Peeked returns the bytes that were peeked so far, or nil if Peek hasn't been called.
func (c *peekConn) Peeked() []byte {
	return c.peeked
}

// Read returns buffered peek data first, then reads from the underlying connection.
func (c *peekConn) Read(p []byte) (int, error) {
	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	return c.Conn.Read(p)
}

// reader returns an io.Reader that replays buffered bytes then reads from conn.
func (c *peekConn) reader() io.Reader {
	if c.buf.Len() > 0 {
		return io.MultiReader(&c.buf, c.Conn)
	}
	return c.Conn
}
