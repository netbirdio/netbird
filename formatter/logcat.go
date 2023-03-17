package formatter

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// LogcatFormatter formats logs into text what is fit for logcat
type LogcatFormatter struct {
	levelDesc []string
}

// NewLogcatFormatter create new LogcatFormatter instance
func NewLogcatFormatter() *LogcatFormatter {
	return &LogcatFormatter{
		levelDesc: []string{"PANC", "FATL", "ERRO", "WARN", "INFO", "DEBG", "TRAC"},
	}
}

// Format renders a single log entry
func (f *LogcatFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var fields string
	keys := make([]string, 0, len(entry.Data))
	for k, v := range entry.Data {
		if k == "source" {
			continue
		}
		keys = append(keys, fmt.Sprintf("%s: %v", k, v))
	}

	if len(keys) > 0 {
		fields = fmt.Sprintf("[%s] ", strings.Join(keys, ", "))
	}

	level := f.parseLevel(entry.Level)

	return []byte(fmt.Sprintf("[%s] %s%s %s\n", level, fields, entry.Data["source"], entry.Message)), nil
}

func (f *LogcatFormatter) parseLevel(level logrus.Level) string {
	if len(f.levelDesc) < int(level) {
		return ""
	}

	return f.levelDesc[level]
}
