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
	arg1   any
	arg2   any
	arg3   any
	arg4   any
	arg5   any
	arg6   any
	arg7   any
	arg8   any
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

func (l *Logger) Error(format string) {
	if l.level.Load() >= uint32(LevelError) {
		select {
		case l.msgChannel <- logMessage{level: LevelError, format: format}:
		default:
		}
	}
}

func (l *Logger) Warn(format string) {
	if l.level.Load() >= uint32(LevelWarn) {
		select {
		case l.msgChannel <- logMessage{level: LevelWarn, format: format}:
		default:
		}
	}
}

func (l *Logger) Info(format string) {
	if l.level.Load() >= uint32(LevelInfo) {
		select {
		case l.msgChannel <- logMessage{level: LevelInfo, format: format}:
		default:
		}
	}
}

func (l *Logger) Debug(format string) {
	if l.level.Load() >= uint32(LevelDebug) {
		select {
		case l.msgChannel <- logMessage{level: LevelDebug, format: format}:
		default:
		}
	}
}

func (l *Logger) Trace(format string) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format}:
		default:
		}
	}
}

func (l *Logger) Error1(format string, arg1 any) {
	if l.level.Load() >= uint32(LevelError) {
		select {
		case l.msgChannel <- logMessage{level: LevelError, format: format, arg1: arg1}:
		default:
		}
	}
}

func (l *Logger) Error2(format string, arg1, arg2 any) {
	if l.level.Load() >= uint32(LevelError) {
		select {
		case l.msgChannel <- logMessage{level: LevelError, format: format, arg1: arg1, arg2: arg2}:
		default:
		}
	}
}

func (l *Logger) Warn3(format string, arg1, arg2, arg3 any) {
	if l.level.Load() >= uint32(LevelWarn) {
		select {
		case l.msgChannel <- logMessage{level: LevelWarn, format: format, arg1: arg1, arg2: arg2, arg3: arg3}:
		default:
		}
	}
}

func (l *Logger) Warn4(format string, arg1, arg2, arg3, arg4 any) {
	if l.level.Load() >= uint32(LevelWarn) {
		select {
		case l.msgChannel <- logMessage{level: LevelWarn, format: format, arg1: arg1, arg2: arg2, arg3: arg3, arg4: arg4}:
		default:
		}
	}
}

func (l *Logger) Debug1(format string, arg1 any) {
	if l.level.Load() >= uint32(LevelDebug) {
		select {
		case l.msgChannel <- logMessage{level: LevelDebug, format: format, arg1: arg1}:
		default:
		}
	}
}

func (l *Logger) Debug2(format string, arg1, arg2 any) {
	if l.level.Load() >= uint32(LevelDebug) {
		select {
		case l.msgChannel <- logMessage{level: LevelDebug, format: format, arg1: arg1, arg2: arg2}:
		default:
		}
	}
}

func (l *Logger) Debug3(format string, arg1, arg2, arg3 any) {
	if l.level.Load() >= uint32(LevelDebug) {
		select {
		case l.msgChannel <- logMessage{level: LevelDebug, format: format, arg1: arg1, arg2: arg2, arg3: arg3}:
		default:
		}
	}
}

func (l *Logger) Trace1(format string, arg1 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1}:
		default:
		}
	}
}

func (l *Logger) Trace2(format string, arg1, arg2 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1, arg2: arg2}:
		default:
		}
	}
}

func (l *Logger) Trace3(format string, arg1, arg2, arg3 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1, arg2: arg2, arg3: arg3}:
		default:
		}
	}
}

func (l *Logger) Trace4(format string, arg1, arg2, arg3, arg4 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1, arg2: arg2, arg3: arg3, arg4: arg4}:
		default:
		}
	}
}

func (l *Logger) Trace5(format string, arg1, arg2, arg3, arg4, arg5 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1, arg2: arg2, arg3: arg3, arg4: arg4, arg5: arg5}:
		default:
		}
	}
}

func (l *Logger) Trace6(format string, arg1, arg2, arg3, arg4, arg5, arg6 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1, arg2: arg2, arg3: arg3, arg4: arg4, arg5: arg5, arg6: arg6}:
		default:
		}
	}
}

// Trace8 logs a trace message with 8 arguments (8 placeholder in format string)
func (l *Logger) Trace8(format string, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8 any) {
	if l.level.Load() >= uint32(LevelTrace) {
		select {
		case l.msgChannel <- logMessage{level: LevelTrace, format: format, arg1: arg1, arg2: arg2, arg3: arg3, arg4: arg4, arg5: arg5, arg6: arg6, arg7: arg7, arg8: arg8}:
		default:
		}
	}
}

func (l *Logger) formatMessage(buf *[]byte, msg logMessage) {
	*buf = (*buf)[:0]
	*buf = time.Now().AppendFormat(*buf, "2006-01-02T15:04:05-07:00")
	*buf = append(*buf, ' ')
	*buf = append(*buf, levelStrings[msg.level]...)
	*buf = append(*buf, ' ')

	// Count non-nil arguments for switch
	argCount := 0
	if msg.arg1 != nil {
		argCount++
		if msg.arg2 != nil {
			argCount++
			if msg.arg3 != nil {
				argCount++
				if msg.arg4 != nil {
					argCount++
					if msg.arg5 != nil {
						argCount++
						if msg.arg6 != nil {
							argCount++
							if msg.arg7 != nil {
								argCount++
								if msg.arg8 != nil {
									argCount++
								}
							}
						}
					}
				}
			}
		}
	}

	var formatted string
	switch argCount {
	case 0:
		formatted = msg.format
	case 1:
		formatted = fmt.Sprintf(msg.format, msg.arg1)
	case 2:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2)
	case 3:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2, msg.arg3)
	case 4:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2, msg.arg3, msg.arg4)
	case 5:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2, msg.arg3, msg.arg4, msg.arg5)
	case 6:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2, msg.arg3, msg.arg4, msg.arg5, msg.arg6)
	case 7:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2, msg.arg3, msg.arg4, msg.arg5, msg.arg6, msg.arg7)
	case 8:
		formatted = fmt.Sprintf(msg.format, msg.arg1, msg.arg2, msg.arg3, msg.arg4, msg.arg5, msg.arg6, msg.arg7, msg.arg8)
	}

	*buf = append(*buf, formatted...)
	*buf = append(*buf, '\n')

	if len(*buf) > maxMessageSize {
		*buf = (*buf)[:maxMessageSize]
	}
}

// processMessage handles a single log message and adds it to the buffer
func (l *Logger) processMessage(msg logMessage, buffer *[]byte) {
	bufp := l.bufPool.Get().(*[]byte)
	defer l.bufPool.Put(bufp)

	l.formatMessage(bufp, msg)

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
