package conntrack

import (
	"bufio"
	"net"
	"net/http"
)

// trackedConn wraps a net.Conn and removes itself from the tracker on Close.
type trackedConn struct {
	net.Conn
	tracker *HijackTracker
	host    string
}

func (c *trackedConn) Close() error {
	c.tracker.remove(c)
	return c.Conn.Close()
}

// trackingWriter wraps an http.ResponseWriter and intercepts Hijack calls
// to replace the raw connection with a trackedConn that auto-deregisters.
type trackingWriter struct {
	http.ResponseWriter
	tracker *HijackTracker
	host    string
}

func (w *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	tc := &trackedConn{Conn: conn, tracker: w.tracker, host: w.host}
	w.tracker.add(tc)
	return tc, buf, nil
}

func (w *trackingWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *trackingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
