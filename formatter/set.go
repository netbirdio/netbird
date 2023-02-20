package formatter

import "github.com/sirupsen/logrus"

// SetTextFormatter set the formatter for given logger.
func SetTextFormatter(logger *logrus.Logger) {
	logger.Formatter = NewMyTextFormatter()
	logger.ReportCaller = true
	logger.AddHook(NewContextHook())
}
