package util

import log "github.com/sirupsen/logrus"

func AddSyslogHook() {
	// The syslog package is not available for Windows. This adapter is needed
	// to handle windows build.
}

func AddSyslogHookToLogger(logger *log.Logger) {
	// The syslog package is not available for Windows. This adapter is needed
	// to handle windows build.
}
