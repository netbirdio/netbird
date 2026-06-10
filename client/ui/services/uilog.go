//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// UILog lets the frontend forward console output into the Go logrus
// pipeline. The JS origin is carried as the "ui" log field so it stays
// distinct from logrus's own Go-caller source.
type UILog struct{}

func NewUILog() *UILog { return &UILog{} }

// Log forwards one frontend console entry. level is trace/debug/info/warn/
// error (anything else → info); source is the JS origin (may be empty).
func (s *UILog) Log(_ context.Context, level, source, msg string) {
	origin := "unknown"
	if source != "" {
		origin = source
	}
	entry := log.WithField("ui", origin)
	switch level {
	case "trace":
		entry.Trace(msg)
	case "debug":
		entry.Debug(msg)
	case "warn", "warning":
		entry.Warn(msg)
	case "error":
		entry.Error(msg)
	default:
		entry.Info(msg)
	}
}
