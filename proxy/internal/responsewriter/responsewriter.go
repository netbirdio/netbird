package responsewriter

import (
	"bufio"
	"net"
	"net/http"
)

// PassthroughWriter wraps an http.ResponseWriter and preserves optional
// interfaces like Hijacker, Flusher, and Pusher by delegating to the underlying
// ResponseWriter if it supports them.
//
// This is the standard pattern for Go middleware that needs to wrap ResponseWriter
// while maintaining support for protocol upgrades (WebSocket), streaming (Flusher),
// and HTTP/2 server push.
type PassthroughWriter struct {
	http.ResponseWriter
}

// New creates a new wrapper around the given ResponseWriter.
func New(w http.ResponseWriter) *PassthroughWriter {
	return &PassthroughWriter{ResponseWriter: w}
}

// Hijack implements http.Hijacker interface if the underlying ResponseWriter supports it.
// This is required for WebSocket connections and other protocol upgrades.
func (w *PassthroughWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush implements http.Flusher interface if the underlying ResponseWriter supports it.
func (w *PassthroughWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Push implements http.Pusher interface if the underlying ResponseWriter supports it.
func (w *PassthroughWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Unwrap returns the underlying ResponseWriter.
// This is required for http.ResponseController (Go 1.20+) to work correctly.
func (w *PassthroughWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
