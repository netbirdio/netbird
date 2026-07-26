package pqkem

import (
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

// EnvLogLevel overrides the ML-KEM manager's slog level (debug/info/warn/error).
// Defaults to info.
const EnvLogLevel = "NB_PQ_MLKEM_LOG_LEVEL"

// NewLogger builds the slog logger for the ML-KEM manager: a text handler to stdout
// at the level from EnvLogLevel. Mirrors the Rosenpass manager's logger setup so PQ
// components log consistently.
func NewLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
}

func logLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvLogLevel))) {
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
