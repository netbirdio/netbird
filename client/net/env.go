package net

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

const (
	envDisableCustomRouting = "NB_DISABLE_CUSTOM_ROUTING"
	envUseLegacyRouting     = "NB_USE_LEGACY_ROUTING"
)

// CustomRoutingDisabled returns true if custom routing is disabled.
// This will fall back to the operation mode before the exit node functionality was implemented.
// In particular exclusion routes won't be set up and all dialers and listeners will use net.Dial and net.Listen, respectively.
func CustomRoutingDisabled() bool {
	if netstack.IsEnabled() {
		return true
	}

	var customRoutingDisabled bool
	if val := os.Getenv(envDisableCustomRouting); val != "" {
		var err error
		customRoutingDisabled, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envDisableCustomRouting, err)
		}
	}

	return customRoutingDisabled
}
