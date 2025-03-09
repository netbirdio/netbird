package syslog

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogSyslogFormat(t *testing.T) {

	someEntry := &logrus.Entry{
		Data:    logrus.Fields{"att1": 1, "att2": 2, "source": "some/fancy/path.go:46"},
		Time:    time.Date(2021, time.Month(2), 21, 1, 10, 30, 0, time.UTC),
		Level:   3,
		Message: "Some Message",
	}

	formatter := NewSyslogFormatter()
	result, _ := formatter.Format(someEntry)

	parsedString := string(result)
	expectedString := "^\\[(att1: 1, att2: 2|att2: 2, att1: 1)\\] Some Message\\s+$"
	assert.Regexp(t, expectedString, parsedString)
}
