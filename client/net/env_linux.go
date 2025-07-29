//go:build linux && !android

package net

import (
	"errors"
	"os"
	"strconv"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

const (
	// these have the same effect, skip socket env supported for backward compatibility
	envSkipSocketMark = "NB_SKIP_SOCKET_MARK"
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
	if val := os.Getenv(envUseLegacyRouting); val != "" {
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
	// temporarily enable advanced routing to check fwmarks are supported
	old := advancedRoutingSupported
	advancedRoutingSupported = true
	defer func() {
		advancedRoutingSupported = old
	}()

	dialer := NewDialer()
	dialer.Timeout = 100 * time.Millisecond

	conn, err := dialer.Dial("udp", "127.0.0.1:9")
	if err != nil {
		log.Warnf("failed to dial with fwmark: %v", err)
		return false
	}

	defer func() {
		if err := conn.Close(); err != nil {
			log.Warnf("failed to close connection: %v", err)
		}
	}()

	if err := conn.SetWriteDeadline(time.Now().Add(time.Millisecond * 100)); err != nil {
		log.Warnf("failed to set write deadline: %v", err)
		return false
	}

	if _, err := conn.Write([]byte("")); err != nil {
		log.Warnf("failed to write to fwmark connection: %v", err)
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

// SetVPNInterfaceName is a no-op on Linux
func SetVPNInterfaceName(name string) {
	// No-op on Linux - not needed for fwmark-based routing
}

// GetVPNInterfaceName returns empty string on Linux
func GetVPNInterfaceName() string {
	return ""
}
