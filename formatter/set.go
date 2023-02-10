package formatter

import "github.com/sirupsen/logrus"

// SetTextFormatter set the formatter for standard logger.
func SetTextFormatter() {
	std := logrus.StandardLogger()
	std.Formatter = NewMyTextFormatter()
	std.ReportCaller = true
	std.AddHook(&ContextHook{})
}
