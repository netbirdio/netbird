//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/sirupsen/logrus"
)

// UILog lets the frontend forward console output into the Go logrus
// pipeline. The JS origin rides in the message ("[ui <file:line>] ...")
// because logrus's ReportCaller always pins the source to this file.
type UILog struct{}

func NewUILog() *UILog { return &UILog{} }

// Log forwards one frontend console entry. level is trace/debug/info/warn/
// error (anything else → info); source is the JS origin (may be empty).
func (s *UILog) Log(_ context.Context, level, source, msg string) {
	if source != "" {
		msg = "[ui " + source + "] " + msg
	} else {
		msg = "[ui] " + msg
	}
	switch level {
	case "trace":
		logrus.Trace(msg)
	case "debug":
		logrus.Debug(msg)
	case "warn", "warning":
		logrus.Warn(msg)
	case "error":
		logrus.Error(msg)
	default:
		logrus.Info(msg)
	}
}
