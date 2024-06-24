package formatter

import (
	"os"

	"github.com/sirupsen/logrus"
)

// SetTextFormatter set the text formatter for given logger.
func SetTextFormatter(logger *logrus.Logger) {
	var formatter logrus.Formatter
	if os.Getenv("NB_LOG_FORMAT") == "json" {
		formatter = &logrus.JSONFormatter{}
	} else {
		formatter = NewTextFormatter()
	}
	logger.Formatter = formatter
	logger.ReportCaller = true
	logger.AddHook(NewContextHook())
}

// SetLogcatFormatter set the logcat formatter for given logger.
func SetLogcatFormatter(logger *logrus.Logger) {
	logger.Formatter = NewLogcatFormatter()
	logger.ReportCaller = true
	logger.AddHook(NewContextHook())
}
