package txt

import (
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
		timestampFormat: "2006-01-02T15:04:05.000Z07:00",
	}
}

func (f *TextFormatter) parseLevel(level logrus.Level) string {
	if len(f.levelDesc) < int(level) {
		return ""
	}

	return f.levelDesc[level]
}
