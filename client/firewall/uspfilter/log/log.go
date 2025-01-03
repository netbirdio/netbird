// Package logger provides a high-performance, non-blocking logger for userspace networking
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
	maxBatchSize         = 1024 * 16  // 16KB max batch size
	maxMessageSize       = 1024 * 2   // 2KB per message
	bufferSize           = 1024 * 256 // 256KB ring buffer
	defaultFlushInterval = 2 * time.Second
)

// Level represents log severity
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

// Logger is a high-performance, non-blocking logger
type Logger struct {
	output    io.Writer
	level     atomic.Uint32
	buffer    *ringBuffer
	shutdown  chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	// Reusable buffer pool for formatting messages
	bufPool sync.Pool
}

func NewFromLogrus(logrusLogger *log.Logger) *Logger {
	l := &Logger{
		output:   logrusLogger.Out,
		buffer:   newRingBuffer(bufferSize),
		shutdown: make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate buffer for message formatting
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

func (l *Logger) SetLevel(level Level) {
	l.level.Store(uint32(level))
}

func (l *Logger) formatMessage(buf *[]byte, level Level, format string, args ...interface{}) {
	*buf = (*buf)[:0]

	// Timestamp
	*buf = time.Now().AppendFormat(*buf, "2006-01-02T15:04:05-07:00")
	*buf = append(*buf, ' ')

	// Level
	*buf = append(*buf, levelStrings[level]...)
	*buf = append(*buf, ' ')

	// Message
	if len(args) > 0 {
		*buf = append(*buf, fmt.Sprintf(format, args...)...)
	} else {
		*buf = append(*buf, format...)
	}

	*buf = append(*buf, '\n')
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	bufp := l.bufPool.Get().(*[]byte)
	l.formatMessage(bufp, level, format, args...)

	if len(*bufp) > maxMessageSize {
		*bufp = (*bufp)[:maxMessageSize]
	}
	_, _ = l.buffer.Write(*bufp)

	l.bufPool.Put(bufp)
}

func (l *Logger) Error(format string, args ...interface{}) {
	if l.level.Load() >= uint32(LevelError) {
		l.log(LevelError, format, args...)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level.Load() >= uint32(LevelWarn) {
		l.log(LevelWarn, format, args...)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.level.Load() >= uint32(LevelInfo) {
		l.log(LevelInfo, format, args...)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level.Load() >= uint32(LevelDebug) {
		l.log(LevelDebug, format, args...)
	}
}

func (l *Logger) Trace(format string, args ...interface{}) {
	if l.level.Load() >= uint32(LevelTrace) {
		l.log(LevelTrace, format, args...)
	}
}

// worker periodically flushes the buffer
func (l *Logger) worker() {
	defer l.wg.Done()

	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()

	buf := make([]byte, 0, maxBatchSize)

	for {
		select {
		case <-l.shutdown:
			return
		case <-ticker.C:
			// Read accumulated messages
			n, _ := l.buffer.Read(buf[:cap(buf)])
			if n == 0 {
				continue
			}

			// Write batch
			_, _ = l.output.Write(buf[:n])
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
