package formatter

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// MyTextFormatter formats logs into text with included source code's path
type MyTextFormatter struct {
	TimestampFormat string
	LevelDesc       []string
}

// NewMyTextFormatter create new MyTextFormatter instance
func NewMyTextFormatter() *MyTextFormatter {
	return &MyTextFormatter{
		LevelDesc:       []string{"PANC", "FATL", "ERRO", "WARN", "INFO", "DEBG"},
		TimestampFormat: time.RFC3339, // or RFC3339
	}
}

// Format renders a single log entry
func (f *MyTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s %s %s: %s\n", entry.Time.Format(f.TimestampFormat), f.LevelDesc[entry.Level], entry.Data["source"], entry.Message)), nil
}
