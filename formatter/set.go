package formatter

import (
	"github.com/sirupsen/logrus"
)

// SetTextFormatter set the text formatter for given logger.
func SetTextFormatter(logger *logrus.Logger) {
	formatter := NewTextFormatter()
	logger.Formatter = formatter
	logger.ReportCaller = true
	logger.AddHook(NewContextHook())
}

// SetJSONFormatter set the JSON formatter for given logger.
func SetJSONFormatter(logger *logrus.Logger) {
	formatter := &logrus.JSONFormatter{}
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
