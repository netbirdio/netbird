package util

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
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

	logPath = "/tmp/netbird/netbird/netbird.log"
	if logPath != "" && logPath != "console" {

		canWrite, _ := canWrite(logPath)
		if canWrite {
			lumberjackLogger := &lumberjack.Logger{
				// Log file absolute path, os agnostic
				Filename:   filepath.ToSlash(logPath),
				MaxSize:    5, // MB
				MaxBackups: 10,
				MaxAge:     30, // days
				Compress:   true,
			}
			log.SetOutput(io.Writer(lumberjackLogger))
		} else {
			fmt.Printf("can't write to %s due to permissions, falling back to log console output\n", logPath)
		}
	}

	logFormatter := new(log.TextFormatter)
	logFormatter.TimestampFormat = time.RFC3339 // or RFC3339
	logFormatter.FullTimestamp = true
	logFormatter.CallerPrettyfier = func(frame *runtime.Frame) (function string, file string) {
		fileName := path.Base(frame.File) + ":" + strconv.Itoa(frame.Line)
		return "", fileName
	}

	if level > log.WarnLevel {
		log.SetReportCaller(true)
	}

	log.SetFormatter(logFormatter)
	log.SetLevel(level)

	return nil
}

func canWrite(filepath string) (bool, error) {
	_, err := os.OpenFile(filepath, os.O_WRONLY, 0666)
	if err != nil {
		if os.IsPermission(err) {
			return false, err
		}
	}
	return true, nil

}

func setWritable(filepath string) error {
	err := os.Chmod(filepath, 0222)
	return err
}

func setReadOnly(filepath string) error {
	err := os.Chmod(filepath, 0444)
	return err
}
