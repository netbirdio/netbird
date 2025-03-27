package ice

import (
	"github.com/pion/logging"
	log "github.com/sirupsen/logrus"
)

// logrusLogger is a wrapper that implements the logging.LeveledLogger interface.
type logrusLogger struct {
	entry *log.Entry
}

func (l *logrusLogger) Trace(msg string) {
	l.entry.Trace(msg)
}

func (l *logrusLogger) Tracef(format string, args ...interface{}) {
	l.entry.Tracef(format, args...)
}

func (l *logrusLogger) Debug(msg string) {
	l.entry.Debug(msg)
}

func (l *logrusLogger) Debugf(format string, args ...interface{}) {
	l.entry.Debugf(format, args...)
}

func (l *logrusLogger) Info(msg string) {
	l.entry.Info(msg)
}

func (l *logrusLogger) Infof(format string, args ...interface{}) {
	l.entry.Infof(format, args...)
}

func (l *logrusLogger) Warn(msg string) {
	l.entry.Warn(msg)
}

func (l *logrusLogger) Warnf(format string, args ...interface{}) {
	l.entry.Warnf(format, args...)
}

func (l *logrusLogger) Error(msg string) {
	l.entry.Error(msg)
}

func (l *logrusLogger) Errorf(format string, args ...interface{}) {
	l.entry.Errorf(format, args...)
}

// logrusFactory implements the logging.LoggerFactory interface.
type logrusFactory struct {
	logger *log.Logger
}

// newLogrusFactory returns a new LoggerFactory that creates logrus-based loggers.
func newLogrusFactory(logger *log.Logger) logging.LoggerFactory {
	return &logrusFactory{logger: logger}
}

func (f *logrusFactory) NewLogger(scope string) logging.LeveledLogger {
	// Create a new logrus entry with a "scope" field.
	entry := f.logger.WithField("scope", scope)
	return &logrusLogger{entry: entry}
}
