package util

import (
	"io"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/netbirdio/netbird/management/server/context"
)

type LogSource string

const (
	LogSourceKey = "logSource"

	HTTPSource   LogSource = "HTTP"
	GRPCSource   LogSource = "GRPC"
	SystemSource LogSource = "SYSTEM"
)

// InitLog parses and sets log-level input
func InitLog(logLevel string, logPath string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.WithContext(ctx).Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}

	if logPath != "" && logPath != "console" {
		lumberjackLogger := &lumberjack.Logger{
			// Log file absolute path, os agnostic
			Filename:   filepath.ToSlash(logPath),
			MaxSize:    5, // MB
			MaxBackups: 10,
			MaxAge:     30, // days
			Compress:   true,
		}
		log.SetOutput(io.Writer(lumberjackLogger))
	}

	log.SetFormatter(NewCustomFormatter())
	log.SetLevel(level)
	return nil
}

// CustomFormatter formats the log message as required
type CustomFormatter struct {
	log.TextFormatter
}

// NewCustomFormatter creates a new CustomFormatter
func NewCustomFormatter() *CustomFormatter {
	formatter := CustomFormatter{}
	formatter.TextFormatter.DisableSorting = true
	return &formatter
}
func (f *CustomFormatter) Format(entry *log.Entry) ([]byte, error) {
	if entry.Context == nil {
		return f.TextFormatter.Format(entry)
	}
	source, ok := entry.Context.Value(LogSourceKey).(LogSource)
	if !ok {
		f.TextFormatter.Format(entry)
	}

	entry.Data["source"] = source
	switch source {
	case HTTPSource:
		return f.formatHTTPLog(entry)
	case GRPCSource:
		return f.formatGRPCLog(entry)
	case SystemSource:
		return f.formatSystemLog(entry)
	default:
		return f.TextFormatter.Format(entry)
	}
}

func (f *CustomFormatter) formatHTTPLog(entry *log.Entry) ([]byte, error) {
	if ctxReqID, ok := entry.Context.Value(context.RequestIDKey).(string); ok {
		entry.Data[context.RequestIDKey] = ctxReqID
	}
	if ctxAccountID, ok := entry.Context.Value(context.AccountIDKey).(string); ok {
		entry.Data[context.AccountIDKey] = ctxAccountID
	}
	if ctxInitiatorID, ok := entry.Context.Value(context.UserIDKey).(string); ok {
		entry.Data[context.UserIDKey] = ctxInitiatorID
	}

	return f.TextFormatter.Format(entry)
}

func (f *CustomFormatter) formatGRPCLog(entry *log.Entry) ([]byte, error) {
	if ctxReqID, ok := entry.Context.Value(context.RequestIDKey).(string); ok {
		entry.Data[context.RequestIDKey] = ctxReqID
	}
	if ctxAccountID, ok := entry.Context.Value(context.AccountIDKey).(string); ok {
		entry.Data[context.AccountIDKey] = ctxAccountID
	}
	if ctxDeviceID, ok := entry.Context.Value(context.PeerIDKey).(string); ok {
		entry.Data[context.PeerIDKey] = ctxDeviceID
	}

	return f.TextFormatter.Format(entry)
}

func (f *CustomFormatter) formatSystemLog(entry *log.Entry) ([]byte, error) {
	if ctxReqID, ok := entry.Context.Value(context.RequestIDKey).(string); ok {
		entry.Data[context.RequestIDKey] = ctxReqID
	}
	if ctxInitiatorID, ok := entry.Context.Value(context.UserIDKey).(string); ok {
		entry.Data[context.UserIDKey] = ctxInitiatorID
	}
	if ctxAccountID, ok := entry.Context.Value(context.AccountIDKey).(string); ok {
		entry.Data[context.AccountIDKey] = ctxAccountID
	}
	if ctxDeviceID, ok := entry.Context.Value(context.PeerIDKey).(string); ok {
		entry.Data[context.PeerIDKey] = ctxDeviceID
	}

	return f.TextFormatter.Format(entry)
}
