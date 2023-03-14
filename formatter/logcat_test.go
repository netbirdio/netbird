package formatter

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestLogcatMessageFormat(t *testing.T) {

	someEntry := &logrus.Entry{
		Data:    logrus.Fields{"att1": 1, "att2": 2, "source": "some/fancy/path.go:46"},
		Time:    time.Date(2021, time.Month(2), 21, 1, 10, 30, 0, time.UTC),
		Level:   3,
		Message: "Some Message",
	}

	formatter := NewLogcatFormatter()
	result, _ := formatter.Format(someEntry)

	expectedString := "[WARN] [att1: 1, att2: 2] some/fancy/path.go:46 Some Message\n"
	expectedStringVariant := "[WARN] [att2: 2, att1: 1] some/fancy/path.go:46 Some Message\n"
	parsedString := string(result)
	if parsedString != expectedString && parsedString != expectedStringVariant {
		t.Errorf("The log messages don't match. Expected: '%s', got: '%s'", expectedString, parsedString)
	}
}
