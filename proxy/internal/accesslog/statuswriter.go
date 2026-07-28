package accesslog

import (
	"io"

	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
)

// statusWriter captures the HTTP status code and bytes written from responses.
// It embeds responsewriter.PassthroughWriter which handles all the optional
// interfaces (Hijacker, Flusher, Pusher) automatically.
type statusWriter struct {
	*responsewriter.PassthroughWriter
	status       int
	bytesWritten int64
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.PassthroughWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.PassthroughWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// bodyCounter wraps an io.ReadCloser and counts bytes read from the request body.
type bodyCounter struct {
	io.ReadCloser
	bytesRead *int64
}

func (bc *bodyCounter) Read(p []byte) (int, error) {
	n, err := bc.ReadCloser.Read(p)
	*bc.bytesRead += int64(n)
	return n, err
}
