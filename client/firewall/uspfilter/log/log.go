// Package log provides a high-performance, non-blocking logger for userspace networking
package log

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	maxBatchSize         = 1024 * 16
	maxMessageSize       = 1024 * 2
	defaultFlushInterval = 2 * time.Second
	logChannelSize       = 1000
)

type Level uint32

const (
	LevelPanic Level = iota
	LevelFatal
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var levelStrings = map[Level]string{
	LevelPanic: "PANC",
	LevelFatal: "FATL",
	LevelError: "ERRO",
	LevelWarn:  "WARN",
	LevelInfo:  "INFO",
	LevelDebug: "DEBG",
	LevelTrace: "TRAC",
}

type logMessage struct {
	level  Level
	format string
	args   []any
}

// Logger is a high-performance, non-blocking logger
type Logger struct {
	output     io.Writer
	level      atomic.Uint32
	msgChannel chan logMessage
	shutdown   chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
	bufPool    sync.Pool
}

// NewFromLogrus creates a new Logger that writes to the same output as the given logrus logger
func NewFromLogrus(logrusLogger *log.Logger) *Logger {
	l := &Logger{
		output:     logrusLogger.Out,
		msgChannel: make(chan logMessage, logChannelSize),
		shutdown:   make(chan struct{}),
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, maxMessageSize)
				return &b
			},
		},
	}

	logrusLevel := logrusLogger.GetLevel()
	l.level.Store(uint32(logrusLevel))
	level := levelStrings[Level(logrusLevel)]
	log.Debugf("New uspfilter logger created with loglevel %v", level)

	l.wg.Add(1)
	go l.worker()

	return l
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level Level) {
	l.level.Store(uint32(level))
	log.Debugf("Set uspfilter logger loglevel to %v", levelStrings[level])
}

func (l *Logger) log(level Level, format string, args ...any) {
	select {
	case l.msgChannel <- logMessage{level: level, format: format, args: args}:
	default:
	}
}

// Error logs a message at error level
func (l *Logger) Error(format string, args ...any) {
	if l.level.Load() >= uint32(LevelError) {
		l.log(LevelError, format, args...)
	}
}

// Warn logs a message at warning level
func (l *Logger) Warn(format string, args ...any) {
	if l.level.Load() >= uint32(LevelWarn) {
		l.log(LevelWarn, format, args...)
	}
}

// Info logs a message at info level
func (l *Logger) Info(format string, args ...any) {
	if l.level.Load() >= uint32(LevelInfo) {
		l.log(LevelInfo, format, args...)
	}
}

// Debug logs a message at debug level
func (l *Logger) Debug(format string, args ...any) {
	if l.level.Load() >= uint32(LevelDebug) {
		l.log(LevelDebug, format, args...)
	}
}

// Trace logs a message at trace level
func (l *Logger) Trace(format string, args ...any) {
	if l.level.Load() >= uint32(LevelTrace) {
		l.log(LevelTrace, format, args...)
	}
}

func (l *Logger) formatMessage(buf *[]byte, level Level, format string, args ...any) {
	*buf = (*buf)[:0]
	*buf = time.Now().AppendFormat(*buf, "2006-01-02T15:04:05-07:00")
	*buf = append(*buf, ' ')
	*buf = append(*buf, levelStrings[level]...)
	*buf = append(*buf, ' ')

	var msg string
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	} else {
		msg = format
	}
	*buf = append(*buf, msg...)
	*buf = append(*buf, '\n')

	if len(*buf) > maxMessageSize {
		*buf = (*buf)[:maxMessageSize]
	}
}

// processMessage handles a single log message and adds it to the buffer
func (l *Logger) processMessage(msg logMessage, buffer *[]byte) {
	bufp := l.bufPool.Get().(*[]byte)
	defer l.bufPool.Put(bufp)

	l.formatMessage(bufp, msg.level, msg.format, msg.args...)

	if len(*buffer)+len(*bufp) > maxBatchSize {
		_, _ = l.output.Write(*buffer)
		*buffer = (*buffer)[:0]
	}
	*buffer = append(*buffer, *bufp...)
}

// flushBuffer writes the accumulated buffer to output
func (l *Logger) flushBuffer(buffer *[]byte) {
	if len(*buffer) > 0 {
		_, _ = l.output.Write(*buffer)
		*buffer = (*buffer)[:0]
	}
}

// processBatch processes as many messages as possible without blocking
func (l *Logger) processBatch(buffer *[]byte) {
	for len(*buffer) < maxBatchSize {
		select {
		case msg := <-l.msgChannel:
			l.processMessage(msg, buffer)
		default:
			return
		}
	}
}

// handleShutdown manages the graceful shutdown sequence with timeout
func (l *Logger) handleShutdown(buffer *[]byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for {
		select {
		case msg := <-l.msgChannel:
			l.processMessage(msg, buffer)
		case <-ctx.Done():
			l.flushBuffer(buffer)
			return
		}

		if len(l.msgChannel) == 0 {
			l.flushBuffer(buffer)
			return
		}
	}
}

// worker is the main goroutine that processes log messages
func (l *Logger) worker() {
	defer l.wg.Done()

	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()

	buffer := make([]byte, 0, maxBatchSize)

	for {
		select {
		case <-l.shutdown:
			l.handleShutdown(&buffer)
			return
		case <-ticker.C:
			l.flushBuffer(&buffer)
		case msg := <-l.msgChannel:
			l.processMessage(msg, &buffer)
			l.processBatch(&buffer)
		}
	}
}

// Stop gracefully shuts down the logger
func (l *Logger) Stop(ctx context.Context) error {
	done := make(chan struct{})

	l.closeOnce.Do(func() {
		close(l.shutdown)
	})

	go func() {
		l.wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}
