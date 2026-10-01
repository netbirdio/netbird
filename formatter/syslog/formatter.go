package syslog

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/formatter/levels"
)

// Formatter formats logs into text
type Formatter struct {
	levelDesc []string
}

// NewSyslogFormatter create new MySyslogFormatter instance
func NewSyslogFormatter() *Formatter {
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
	return []byte(fmt.Sprintf("%s%s\n", fields, entry.Message)), nil
}
