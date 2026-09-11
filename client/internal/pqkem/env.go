package pqkem

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvEnabled is the environment variable that turns the ML-KEM post-quantum
// exchange on for this client. Accepts on/off aliases plus anything
// strconv.ParseBool understands (true/false/1/0).
const EnvEnabled = "NB_ENABLE_PQ_MLKEM"

// Enabled reports whether the ML-KEM PQ exchange is enabled via the environment.
// An empty or unrecognized value is treated as disabled.
func Enabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(EnvEnabled)))
	switch raw {
	case "":
		return false
	case "on":
		return true
	case "off":
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		log.Warnf("failed to parse %s value %q: %v", EnvEnabled, raw, err)
		return false
	}
	return enabled
}

// EnvStrict enables strict (fail-closed) mode: block peer traffic until the ML-KEM
// PSK has been established, instead of the default opportunistic behaviour that lets
// the tunnel come up classically and upgrades to PQ once the exchange converges.
const EnvStrict = "NB_PQ_MLKEM_STRICT"

// Strict reports whether strict (fail-closed) mode is enabled via the environment.
// An empty or unrecognized value is treated as disabled (opportunistic).
func Strict() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvStrict))) {
	case "on":
		return true
	case "", "off":
		return false
	}
	enabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(EnvStrict)))
	if err != nil {
		log.Warnf("failed to parse %s value %q: %v", EnvStrict, os.Getenv(EnvStrict), err)
		return false
	}
	return enabled
}

// EnvLogLevel overrides the ML-KEM manager's slog level (trace/debug/info/warn/error).
// Defaults to info. The verbose per-exchange lifecycle logs are emitted at trace.
const EnvLogLevel = "NB_PQ_MLKEM_LOG_LEVEL"

// LevelTrace is a custom slog level below Debug for the verbose per-exchange lifecycle
// logs, so they stay off unless NB_PQ_MLKEM_LOG_LEVEL=trace (and the daemon log level
// is trace, since the records are forwarded to logrus).
const LevelTrace = slog.LevelDebug - 4

// NewLogger builds the slog logger for the ML-KEM manager. It forwards records to
// logrus so PQ logs land in the same sink as the rest of the daemon (console +
// client.log) rather than stdout. Verbosity is gated by EnvLogLevel.
func NewLogger() *slog.Logger {
	return slog.New(slogToLogrus{})
}

func logLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvLogLevel))) {
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// slogToLogrus is a slog.Handler that forwards records to logrus, so the ML-KEM
// manager's logs go wherever the daemon's logrus is configured (console + client.log)
// instead of stdout. Verbosity is gated by EnvLogLevel via logLevel().
type slogToLogrus struct {
	fields log.Fields
}

func (h slogToLogrus) Enabled(_ context.Context, level slog.Level) bool {
	return level >= logLevel()
}

func (h slogToLogrus) Handle(_ context.Context, r slog.Record) error {
	fields := make(log.Fields, len(h.fields)+r.NumAttrs())
	for k, v := range h.fields {
		fields[k] = v
	}
	r.Attrs(func(a slog.Attr) bool {
		fields[a.Key] = a.Value.Any()
		return true
	})
	entry := log.WithFields(fields)
	switch {
	case r.Level >= slog.LevelError:
		entry.Error(r.Message)
	case r.Level >= slog.LevelWarn:
		entry.Warn(r.Message)
	case r.Level >= slog.LevelInfo:
		entry.Info(r.Message)
	case r.Level >= slog.LevelDebug:
		entry.Debug(r.Message)
	default:
		entry.Trace(r.Message)
	}
	return nil
}

func (h slogToLogrus) WithAttrs(attrs []slog.Attr) slog.Handler {
	fields := make(log.Fields, len(h.fields)+len(attrs))
	for k, v := range h.fields {
		fields[k] = v
	}
	for _, a := range attrs {
		fields[a.Key] = a.Value.Any()
	}
	return slogToLogrus{fields: fields}
}

func (h slogToLogrus) WithGroup(_ string) slog.Handler { return h }
