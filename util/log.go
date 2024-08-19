package util

import (
	"io"
	"os"
	"path/filepath"
	"slices"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/netbirdio/netbird/formatter"
)

// InitLog parses and sets log-level input
func InitLog(logLevel string, logPath string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}
	customOutputs := []string{"console", "syslog"};

	if logPath != "" && !slices.Contains(customOutputs, logPath) {
		lumberjackLogger := &lumberjack.Logger{
			// Log file absolute path, os agnostic
			Filename:   filepath.ToSlash(logPath),
			MaxSize:    5, // MB
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
	return nil
}
