package formatter

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// TextFormatter formats logs into text with included source code's path
type TextFormatter struct {
	timestampFormat string
	levelDesc       []string
}

// NewTextFormatter create new MyTextFormatter instance
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		levelDesc:       []string{"PANC", "FATL", "ERRO", "WARN", "INFO", "DEBG", "TRAC"},
		timestampFormat: time.RFC3339, // or RFC3339
	}
}

// Format renders a single log entry
func (f *TextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
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

	return []byte(fmt.Sprintf("%s %s %s%s: %s\n", entry.Time.Format(f.timestampFormat), level, fields, entry.Data["source"], entry.Message)), nil
}

func (f *TextFormatter) parseLevel(level logrus.Level) string {
	if len(f.levelDesc) < int(level) {
		return ""
	}

	return f.levelDesc[level]
}
