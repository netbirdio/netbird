package util

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/grpclog"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/netbirdio/netbird/formatter"
)

const defaultLogSize = 15

const (
	LogConsole = "console"
	LogSyslog  = "syslog"
)

var (
	SpecialLogs = []string{
		LogSyslog,
		LogConsole,
	}
)

// InitLog parses and sets log-level input
func InitLog(logLevel string, logs ...string) error {
	return InitLogger(log.StandardLogger(), logLevel, logs...)
}

// InitLogger parses and sets log-level input for a logrus logger
func InitLogger(logger *log.Logger, logLevel string, logs ...string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		logger.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}
	var writers []io.Writer
	logFmt := os.Getenv("NB_LOG_FORMAT")

	for _, logPath := range logs {
		switch logPath {
		case LogSyslog:
			AddSyslogHookToLogger(logger)
			logFmt = "syslog"
		case LogConsole:
			writers = append(writers, os.Stderr)
		case "":
			logger.Warnf("empty log path received: %#v", logPath)
		default:
			writers = append(writers, newRotatedOutput(logPath))
		}
	}

	if len(writers) > 1 {
		logger.SetOutput(io.MultiWriter(writers...))
	} else if len(writers) == 1 {
		logger.SetOutput(writers[0])
	}

	switch logFmt {
	case "json":
		formatter.SetJSONFormatter(logger)
	case "syslog":
		formatter.SetSyslogFormatter(logger)
	default:
		formatter.SetTextFormatter(logger)
	}
	logger.SetLevel(level)

	setGRPCLibLogger(logger)

	return nil
}

// FindFirstLogPath returns the first logs entry that could be a log path, that is neither empty, nor a special value
func FindFirstLogPath(logs []string) string {
	for _, logFile := range logs {
		if logFile != "" && !slices.Contains(SpecialLogs, logFile) {
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

func setGRPCLibLogger(logger *log.Logger) {
	logOut := logger.Writer()
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
