package accesslog

import (
	"github.com/netbirdio/netbird/proxy/internal/responsewriter"
)

// statusWriter captures the HTTP status code from WriteHeader calls.
// It embeds responsewriter.PassthroughWriter which handles all the optional
// interfaces (Hijacker, Flusher, Pusher) automatically.
type statusWriter struct {
	*responsewriter.PassthroughWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.PassthroughWriter.WriteHeader(status)
}
