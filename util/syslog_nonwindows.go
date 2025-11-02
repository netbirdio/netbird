//go:build !windows

package util

import (
	"log/syslog"

	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

func AddSyslogHook() {
	hook, err := lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")

	if err != nil {
		log.Errorf("Failed creating syslog hook: %s", err)
	}
	log.AddHook(hook)
}
