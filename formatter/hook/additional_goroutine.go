//go:build loggoroutine

package hook

import (
	"bytes"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func additionalEntries(entry *log.Entry) {
	entry.Data[EntryKeyGoroutineID] = getGoroutineID()
}

func getGoroutineID() int {
	buf := make([]byte, 64)
	buf = buf[:runtime.Stack(buf, false)]
	fields := bytes.Fields(buf)
	if len(fields) < 2 {
		return -1
	}
	id, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return -1
	}
	return id
}
