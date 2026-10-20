//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	log "github.com/sirupsen/logrus"
)

// UILog forwards frontend console output into logrus, tagging the JS origin
// as the "ui" field to stay distinct from logrus's Go-caller source.
type UILog struct{}

func NewUILog() *UILog { return &UILog{} }

// Log maps an unrecognised level to info; empty source becomes "unknown".
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
