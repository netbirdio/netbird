//go:build !loggoroutine

package hook

import log "github.com/sirupsen/logrus"

func additionalEntries(_ *log.Entry) {
	// This function is empty and is used to demonstrate the use of additional hooks.
}
