package util

import (
	"io"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/grpclog"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/netbirdio/netbird/formatter"
)

const defaultLogSize = 15

const (
	// LogSeparator preserves compatibility with cobra's StringSliceVar() by using `,`
	LogSeparator = ","
	LogConsole   = "console"
	LogSyslog    = "syslog"
)

var (
	SpecialLogs = []string{
		LogSyslog,
		LogConsole,
	}
)

// InitLog parses and sets log-level input
func InitLog(logLevel string, logs ...string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}
	var writers []io.Writer
	logFmt := os.Getenv("NB_LOG_FORMAT")

	for logPath := range IterateLogs(logs) {
		switch logPath {
		case LogSyslog:
			AddSyslogHook()
			logFmt = "syslog"
		case LogConsole:
			writers = append(writers, os.Stderr)
		case "":
			log.Warnf("empty log path received: %#v", logPath)
		default:
			writers = append(writers, newRotatedOutput(logPath))
		}
	}

	if len(writers) > 1 {
		log.SetOutput(io.MultiWriter(writers...))
	} else if len(writers) == 1 {
		log.SetOutput(writers[0])
	}

	switch logFmt {
	case "json":
		formatter.SetJSONFormatter(log.StandardLogger())
	case "syslog":
		formatter.SetSyslogFormatter(log.StandardLogger())
	default:
		formatter.SetTextFormatter(log.StandardLogger())
	}
	log.SetLevel(level)

	setGRPCLibLogger()

	return nil
}

// IterateLogs parses and iterates over logging entries
func IterateLogs(logs []string) iter.Seq[string] {
	return func(yield func(string) bool) {
		parts := strings.Split(strings.Join(logs, LogSeparator), LogSeparator)
		for _, part := range parts {
			if !yield(strings.TrimSpace(part)) {
				return
			}
		}
	}
}

// FindFirstLogPath locates the first non-special logfile, assumed to be a valid path
func FindFirstLogPath(logs []string) string {
	for logFile := range IterateLogs(logs) {
		if !slices.Contains(SpecialLogs, logFile) {
			return logFile
		}
	}
	return ""
}

func newRotatedOutput(logPath string) io.Writer {
	maxLogSize := getLogMaxSize()
	lumberjackLogger := &lumberjack.Logger{
		// Log file absolute path, os agnostic
		Filename:   filepath.ToSlash(logPath),
		MaxSize:    maxLogSize, // MB
		MaxBackups: 10,
		MaxAge:     30, // days
		Compress:   true,
	}
	return lumberjackLogger
}

func setGRPCLibLogger() {
	logOut := log.StandardLogger().Writer()
	if os.Getenv("GRPC_GO_LOG_SEVERITY_LEVEL") != "info" {
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, logOut, logOut))
		return
	}

	var v int
	vLevel := os.Getenv("GRPC_GO_LOG_VERBOSITY_LEVEL")
	if vl, err := strconv.Atoi(vLevel); err == nil {
		v = vl
	}

	grpclog.SetLoggerV2(grpclog.NewLoggerV2WithVerbosity(logOut, logOut, logOut, v))
}

func getLogMaxSize() int {
	if sizeVar, ok := os.LookupEnv("NB_LOG_MAX_SIZE_MB"); ok {
		size, err := strconv.ParseInt(sizeVar, 10, 64)
		if err != nil {
			log.Errorf("Failed parsing log-size %s: %s. Should be just an integer", sizeVar, err)
			return defaultLogSize
		}

		log.Infof("Setting log file max size to %d MB", size)

		return int(size)
	}
	return defaultLogSize
}
