package txt

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/formatter/levels"
)

// TextFormatter formats logs into text with included source code's path
type TextFormatter struct {
	timestampFormat string
	levelDesc       []string
}

// NewTextFormatter create new MyTextFormatter instance
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		levelDesc:       levels.ValidLevelDesc,
		timestampFormat: time.RFC3339, // or RFC3339
	}
}

func (f *TextFormatter) parseLevel(level logrus.Level) string {
	if len(f.levelDesc) < int(level) {
		return ""
	}

	return f.levelDesc[level]
}
