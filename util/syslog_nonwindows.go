//go:build !windows

package util

import (
	"log/syslog"

	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

func AddSyslogHook() {
	AddSyslogHookToLogger(log.StandardLogger())
}

func AddSyslogHookToLogger(logger *log.Logger) {
	hook, err := lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")

	if err != nil {
		logger.Errorf("Failed creating syslog hook: %s", err)
	}
	logger.AddHook(hook)
}
