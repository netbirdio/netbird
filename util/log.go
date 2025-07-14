package util

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/grpclog"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/netbirdio/netbird/formatter"
)

const defaultLogSize = 15

// InitLog parses and sets log-level input
func InitLog(logLevel string, logPaths string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}
	var writers []io.Writer
	logFmt := os.Getenv("NB_LOG_FORMAT")

	for _, logPath := range strings.Split(logPaths, ":") {
		switch logPath {
		case "syslog":
			AddSyslogHook()
			logFmt = "syslog"
		case "console", "docker", "stderr":
			writers = append(writers, os.Stderr)
		case "":
			log.Warnf("empty log path received: %#v", logPath)
		default:
			maxLogSize := getLogMaxSize()
			lumberjackLogger := &lumberjack.Logger{
				// Log file absolute path, os agnostic
				Filename:   filepath.ToSlash(logPath),
				MaxSize:    maxLogSize, // MB
				MaxBackups: 10,
				MaxAge:     30, // days
				Compress:   true,
			}
			writers = append(writers, lumberjackLogger)
		}
	}
	if len(writers) > 0 {
		log.SetOutput(io.MultiWriter(writers...))
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
