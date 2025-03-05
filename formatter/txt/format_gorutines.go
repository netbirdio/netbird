//go:build loggoroutine

package txt

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/formatter/hook"
)

func (f *TextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var fields string
	keys := make([]string, 0, len(entry.Data))
	for k, v := range entry.Data {
		if k == hook.EntryKeySource {
			continue
		}

		if k == hook.EntryKeyGoroutineID {
			continue
		}
		keys = append(keys, fmt.Sprintf("%s: %v", k, v))
	}

	if len(keys) > 0 {
		fields = fmt.Sprintf("[%s] ", strings.Join(keys, ", "))
	}

	level := f.parseLevel(entry.Level)

	return []byte(fmt.Sprintf("%s %s %d %s%s: %s\n", entry.Time.Format(f.timestampFormat), level, entry.Data[hook.EntryKeyGoroutineID], fields, entry.Data[hook.EntryKeySource], entry.Message)), nil
}
