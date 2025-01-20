//go:build linux && !android

package net

import (
	"errors"
	"os"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

const (
	// these have the same effect, skip socket env supported for backward compatibility
	envSkipSocketMark   = "NB_SKIP_SOCKET_MARK"
	envUseLegacyRouting = "NB_USE_LEGACY_ROUTING"
)

var advancedRoutingSupported bool

func Init() {
	advancedRoutingSupported = checkAdvancedRoutingSupport()
}

func AdvancedRouting() bool {
	return advancedRoutingSupported
}

func checkAdvancedRoutingSupport() bool {
	var err error

	var legacyRouting bool
	if val := os.Getenv("NB_USE_LEGACY_ROUTING"); val != "" {
		legacyRouting, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envUseLegacyRouting, err)
		}
	}

	var skipSocketMark bool
	if val := os.Getenv(envSkipSocketMark); val != "" {
		skipSocketMark, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envSkipSocketMark, err)
		}
	}

	// requested to disable advanced routing
	if legacyRouting || skipSocketMark ||
		// envCustomRoutingDisabled disables the custom dialers.
		// There is no point in using advanced routing without those, as they set up fwmarks on the sockets.
		CustomRoutingDisabled() ||
		// netstack mode doesn't need routing at all
		netstack.IsEnabled() {

		log.Info("advanced routing has been requested to be disabled")
		return false
	}

	if !CheckFwmarkSupport() || !CheckRuleOperationsSupport() {
		log.Warn("system doesn't support required routing features, falling back to legacy routing")
		return false
	}

	log.Info("system supports advanced routing")

	return true
}

func CheckFwmarkSupport() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		log.Warnf("failed to create test socket: %v", err)
		return false
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, NetbirdFwmark)
	if err != nil {
		log.Warnf("fwmark is not supported: %v", err)
		return false
	}
	return true
}

func CheckRuleOperationsSupport() bool {
	rule := netlink.NewRule()
	// low precedence, semi-random
	rule.Priority = 32321
	rule.Table = syscall.RT_TABLE_MAIN
	rule.Family = netlink.FAMILY_V4

	if err := netlink.RuleAdd(rule); err != nil {
		if errors.Is(err, syscall.EOPNOTSUPP) {
			log.Warn("IP rule operations are not supported")
			return false
		}
		log.Warnf("failed to test rule support: %v", err)
		return false
	}

	if err := netlink.RuleDel(rule); err != nil {
		log.Warnf("failed to delete test rule: %v", err)
	}
	return true
}
