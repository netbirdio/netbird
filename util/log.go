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

// InitLog parses and sets log-level input
func InitLog(logLevel string, logPath string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}
	customOutputs := []string{"console", "syslog"}

	if logPath != "" && !slices.Contains(customOutputs, logPath) {
		maxLogSize := getLogMaxSize()
		lumberjackLogger := &lumberjack.Logger{
			// Log file absolute path, os agnostic
			Filename:   filepath.ToSlash(logPath),
			MaxSize:    maxLogSize, // MB
			MaxBackups: 10,
			MaxAge:     30, // days
			Compress:   true,
		}
		log.SetOutput(io.Writer(lumberjackLogger))
	} else if logPath == "syslog" {
		AddSyslogHook()
	}

	//nolint:gocritic
	if os.Getenv("NB_LOG_FORMAT") == "json" {
		formatter.SetJSONFormatter(log.StandardLogger())
	} else if logPath == "syslog" {
		formatter.SetSyslogFormatter(log.StandardLogger())
	} else {
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
