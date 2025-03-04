//go:build !loggoroutine

package hook

import log "github.com/sirupsen/logrus"

func additionalEntries(_ *log.Entry) {
}
