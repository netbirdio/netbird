//go:build windows

package net

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	envUseLegacyRouting = "NB_USE_LEGACY_ROUTING"
)

var advancedRoutingSupported bool

// Init initializes the network stack for Windows
func Init() {
	advancedRoutingSupported = checkAdvancedRoutingSupport()
}

func checkAdvancedRoutingSupport() bool {
	var useLegacy bool
	if val := os.Getenv(envUseLegacyRouting); val != "" {
		var err error
		useLegacy, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envUseLegacyRouting, err)
		}
	}

	if useLegacy {
		log.Info("Legacy routing requested via environment variable")
		return false
	}

	if CustomRoutingDisabled() {
		log.Info("Custom routing disabled, using legacy routing")
		return false
	}

	log.Info("Advanced routing (IP_UNICAST_IF) is enabled on Windows")
	return true
}

// AdvancedRouting returns true if IpUnicastIf-based routing is supported
func AdvancedRouting() bool {
	return advancedRoutingSupported
}
