package util

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// InitLog parses and sets log-level input
func InitLog(logLevel string, logPath string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		return err
	}

	if logPath != "" && logPath != "console" {
		lumberjackLogger := &lumberjack.Logger{
			// Log file absolute path, os agnostic
			Filename:   filepath.ToSlash(logPath),
			MaxSize:    5, // MB
			MaxBackups: 10,
			MaxAge:     30, // days
			Compress:   true,
		}
		log.SetOutput(io.Writer(lumberjackLogger))
	}

	logFormatter := new(log.TextFormatter)
	logFormatter.TimestampFormat = time.RFC3339 // or RFC3339
	logFormatter.FullTimestamp = true
	logFormatter.CallerPrettyfier = func(frame *runtime.Frame) (function string, file string) {
		fileName := path.Base(frame.File) + ":" + strconv.Itoa(frame.Line)
		//return frame.Function, fileName
		return "", fileName
	}

	if level == log.DebugLevel {
		log.SetReportCaller(true)
	}

	log.SetFormatter(logFormatter)
	log.SetLevel(level)

	return nil
}
