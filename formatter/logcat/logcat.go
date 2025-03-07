package logcat

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/formatter/levels"
)

// Formatter formats logs into text what is fit for logcat
type Formatter struct {
	levelDesc []string
}

// NewLogcatFormatter create new LogcatFormatter instance
func NewLogcatFormatter() *Formatter {
	return &Formatter{
		levelDesc: levels.ValidLevelDesc,
	}
}

// Format renders a single log entry
func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
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

func (f *Formatter) parseLevel(level logrus.Level) string {
	if len(f.levelDesc) < int(level) {
		return ""
	}

	return f.levelDesc[level]
}
