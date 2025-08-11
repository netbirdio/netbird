//go:build windows

package net

import (
	"os"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

var (
	vpnInterfaceName string
	vpnInitMutex     sync.RWMutex

	advancedRoutingSupported bool
)

func Init() {
	advancedRoutingSupported = checkAdvancedRoutingSupport()
}

func checkAdvancedRoutingSupport() bool {
	var err error
	var legacyRouting bool
	if val := os.Getenv(envUseLegacyRouting); val != "" {
		legacyRouting, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envUseLegacyRouting, err)
		}
	}

	if legacyRouting || netstack.IsEnabled() {
		log.Info("advanced routing has been requested to be disabled")
		return false
	}

	log.Info("system supports advanced routing")

	return true
}

// AdvancedRouting reports whether routing loops can be avoided without using exclusion routes
func AdvancedRouting() bool {
	return advancedRoutingSupported
}

// GetVPNInterfaceName returns the stored VPN interface name
func GetVPNInterfaceName() string {
	vpnInitMutex.RLock()
	defer vpnInitMutex.RUnlock()
	return vpnInterfaceName
}

// SetVPNInterfaceName sets the VPN interface name for lazy initialization
func SetVPNInterfaceName(name string) {
	vpnInitMutex.Lock()
	defer vpnInitMutex.Unlock()
	vpnInterfaceName = name

	if name != "" {
		log.Infof("VPN interface name set to %s for route exclusion", name)
	}
}
