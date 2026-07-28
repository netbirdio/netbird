package dex

import (
	"context"
	"log/slog"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/formatter"
)

// LogrusHandler is an slog.Handler that delegates to logrus.
// This allows Dex to use the same log format as the rest of NetBird.
type LogrusHandler struct {
	logger *logrus.Logger
	attrs  []slog.Attr
	groups []string
}

// NewLogrusHandler creates a new slog handler that wraps logrus with NetBird's text formatter.
func NewLogrusHandler(level slog.Level) *LogrusHandler {
	logger := logrus.New()
	formatter.SetTextFormatter(logger)

	// Map slog level to logrus level
	switch level {
	case slog.LevelDebug:
		logger.SetLevel(logrus.DebugLevel)
	case slog.LevelInfo:
		logger.SetLevel(logrus.InfoLevel)
	case slog.LevelWarn:
		logger.SetLevel(logrus.WarnLevel)
	case slog.LevelError:
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.WarnLevel)
	}

	return &LogrusHandler{logger: logger}
}

// Enabled reports whether the handler handles records at the given level.
func (h *LogrusHandler) Enabled(_ context.Context, level slog.Level) bool {
	switch level {
	case slog.LevelDebug:
		return h.logger.IsLevelEnabled(logrus.DebugLevel)
	case slog.LevelInfo:
		return h.logger.IsLevelEnabled(logrus.InfoLevel)
	case slog.LevelWarn:
		return h.logger.IsLevelEnabled(logrus.WarnLevel)
	case slog.LevelError:
		return h.logger.IsLevelEnabled(logrus.ErrorLevel)
	default:
		return true
	}
}

// Handle handles the Record.
func (h *LogrusHandler) Handle(_ context.Context, r slog.Record) error {
	fields := make(logrus.Fields)

	// Add pre-set attributes
	for _, attr := range h.attrs {
		fields[attr.Key] = attr.Value.Any()
	}

	// Add record attributes
	r.Attrs(func(attr slog.Attr) bool {
		fields[attr.Key] = attr.Value.Any()
		return true
	})

	entry := h.logger.WithFields(fields)

	switch r.Level {
	case slog.LevelDebug:
		entry.Debug(r.Message)
	case slog.LevelInfo:
		entry.Info(r.Message)
	case slog.LevelWarn:
		entry.Warn(r.Message)
	case slog.LevelError:
		entry.Error(r.Message)
	default:
		entry.Info(r.Message)
	}

	return nil
}

// WithAttrs returns a new Handler with the given attributes added.
func (h *LogrusHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &LogrusHandler{
		logger: h.logger,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

// WithGroup returns a new Handler with the given group appended to the receiver's groups.
func (h *LogrusHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups[len(h.groups)] = name
	return &LogrusHandler{
		logger: h.logger,
		attrs:  h.attrs,
		groups: newGroups,
	}
}
