package formatter

import "github.com/sirupsen/logrus"

// SetTextFormatter set the text formatter for given logger.
func SetTextFormatter(logger *logrus.Logger) {
	logger.Formatter = NewTextFormatter()
	logger.ReportCaller = true
	logger.AddHook(NewContextHook())
}

// SetLogcatFormatter set the logcat formatter for given logger.
func SetLogcatFormatter(logger *logrus.Logger) {
	logger.Formatter = NewLogcatFormatter()
	logger.ReportCaller = true
	logger.AddHook(NewContextHook())
}
