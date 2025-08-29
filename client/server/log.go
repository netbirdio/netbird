package server

import (
	"strings"

	"github.com/netbirdio/netbird/client/proto"
)

func ParseLogLevel(level string) proto.LogLevel {
	switch strings.ToLower(level) {
	case "panic":
		return proto.LogLevel_PANIC
	case "fatal":
		return proto.LogLevel_FATAL
	case "error":
		return proto.LogLevel_ERROR
	case "warn":
		return proto.LogLevel_WARN
	case "info":
		return proto.LogLevel_INFO
	case "debug":
		return proto.LogLevel_DEBUG
	case "trace":
		return proto.LogLevel_TRACE
	default:
		return proto.LogLevel_UNKNOWN
	}
}
