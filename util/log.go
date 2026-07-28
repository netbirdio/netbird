package util

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/DeRuina/timberjack"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/grpclog"

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
		return fmt.Errorf("failed parsing log-level %s: %w", logLevel, err)
	}

	logFmt, err := buildWriters(logger, logs...)
	if err != nil {
		return err
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

// SetLogOutputs re-points an already-initialized logger to the given targets
// (console/syslog/file), with the same target semantics as InitLogger, but
// without re-parsing the level or resetting the formatter. The desktop GUI uses
// it to attach the rotated gui-client.log alongside the console when the daemon
// enters debug, and drop back to console-only when it leaves.
func SetLogOutputs(logger *log.Logger, logs ...string) error {
	if _, err := buildWriters(logger, logs...); err != nil {
		return err
	}
	setGRPCLibLogger(logger)
	return nil
}

// buildWriters resolves the given log targets to writers and points the logger
// at them (single writer or MultiWriter). It returns the log format implied by
// the targets (syslog forces "syslog"; otherwise the NB_LOG_FORMAT env value).
// Shared by InitLogger and SetLogOutputs.
func buildWriters(logger *log.Logger, logs ...string) (string, error) {
	var writers []io.Writer
	logFmt := os.Getenv("NB_LOG_FORMAT")

	seen := make(map[string]bool, len(logs))
	for _, logPath := range logs {
		if seen[logPath] {
			continue
		}
		seen[logPath] = true

		switch logPath {
		case LogSyslog:
			AddSyslogHookToLogger(logger)
			logFmt = "syslog"
		case LogConsole:
			writers = append(writers, os.Stderr)
		case "":
			logger.Warnf("empty log path received: %#v", logPath)
		default:
			writer, err := setupLogFile(logPath, isRotationDisabled(logger))
			if err != nil {
				return "", fmt.Errorf("failed setting up log file: %s, %w", logPath, err)
			}
			writers = append(writers, writer)
		}
	}

	if len(writers) > 1 {
		logger.SetOutput(io.MultiWriter(writers...))
	} else if len(writers) == 1 {
		logger.SetOutput(writers[0])
	}

	return logFmt, nil
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

func isRotationDisabled(logger *log.Logger) bool {
	v, _ := os.LookupEnv("NB_LOG_DISABLE_ROTATION")
	disabled, _ := strconv.ParseBool(v)
	if disabled {
		logger.Warnf("log rotation is disabled by env flag")
		return true
	}
	conflict, configPath := FindFirstLogrotateConflict()
	if conflict {
		logger.Warnf("log rotation conflict detected in: %#v, rotation is disabled", configPath)
		return true
	}
	return false
}

func setupLogFile(logPath string, disableRotation bool) (io.Writer, error) {
	if disableRotation {
		file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	return newRotatedOutput(logPath), nil
}

func newRotatedOutput(logPath string) io.Writer {
	maxLogSize := getLogMaxSize()
	timberjackLogger := &timberjack.Logger{
		// Log file absolute path, os agnostic
		Filename:    filepath.ToSlash(logPath),
		MaxSize:     maxLogSize, // MB
		MaxBackups:  10,
		MaxAge:      30, // days
		Compression: "gzip",
	}
	return timberjackLogger
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
			log.Errorf("failed parsing log-size %s: %s. Should be just an integer", sizeVar, err)
			return defaultLogSize
		}

		log.Infof("Setting log file max size to %d MB", size)

		return int(size)
	}
	return defaultLogSize
}
