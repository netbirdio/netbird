//go:build loggoroutine

package hook

import (
	"github.com/petermattis/goid"
	log "github.com/sirupsen/logrus"
)

func additionalEntries(entry *log.Entry) {
	entry.Data[EntryKeyGoroutineID] = goid.Get()
}
