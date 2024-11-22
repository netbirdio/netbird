package net

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

const (
	envDisableCustomRouting = "NB_DISABLE_CUSTOM_ROUTING"
	envSkipSocketMark       = "NB_SKIP_SOCKET_MARK"
)

func CustomRoutingDisabled() bool {
	if netstack.IsEnabled() {
		return true
	}
	return os.Getenv(envDisableCustomRouting) == "true"
}

func SkipSocketMark() bool {
	if skipSocketMark := os.Getenv(envSkipSocketMark); skipSocketMark == "true" {
		log.Infof("%s is set to true, skipping SO_MARK", envSkipSocketMark)
		return true
	}
	return false
}
