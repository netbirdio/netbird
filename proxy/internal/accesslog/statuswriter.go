package accesslog

import (
	"net/http"
)

// statusWriter is a simple wrapper around an http.ResponseWriter
// that captures the setting of the status code via the WriteHeader
// function and stores it so that it can be retrieved later.
type statusWriter struct {
	w      http.ResponseWriter
	status int
}

func (w *statusWriter) Header() http.Header {
	return w.w.Header()
}

func (w *statusWriter) Write(data []byte) (int, error) {
	return w.w.Write(data)
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.w.WriteHeader(status)
}
