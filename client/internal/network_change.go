package internal

import (
	"os"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// EnvDisableNetworkChangeRedial restores the full client restart on every
// network change, as a field switch should the redial path misbehave.
const EnvDisableNetworkChangeRedial = "NB_DISABLE_NETWORK_CHANGE_REDIAL"

// underlayPinnedAtStart reports the platforms that bind NetBird's own sockets
// to the underlay interface once, at engine start: macOS (scoped default plus
// IP_BOUND_IF) and Windows (IP_UNICAST_IF on the WireGuard socket). Until that
// binding can be refreshed in place, a change there still needs a restart.
const underlayPinnedAtStart = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// handleUnderlayChange moves the control connections to the new underlay
// without restarting the client. It returns false when only a restart can
// recover from the change.
func (e *Engine) handleUnderlayChange(change networkmonitor.Change) bool {
	if !canHandleWithoutRestart(change, e.netMgr != nil) {
		return false
	}

	log.Infof("Network monitor: underlay %s change, redialing control connections without restart", change.Kind)
	log.Debugf("Network monitor: underlay next hops v4 %s -> %s, v6 %s -> %s",
		change.Before.V4, change.After.V4, change.Before.V6, change.After.V6)
	e.netMgr.NotifyNetworkChange()
	return true
}

// canHandleWithoutRestart keeps the restart for an unchanged underlay (a flap
// or a wake-up, where the restart is the only recovery today), for legacy
// routing, whose /32 infra routes point at the old gateway, and for platforms
// that pin the underlay at start.
func canHandleWithoutRestart(change networkmonitor.Change, hasNetEvents bool) bool {
	if !hasNetEvents || change.Kind == networkmonitor.ChangeNone || redialDisabledByEnv() {
		return false
	}
	if !nbnet.AdvancedRouting() {
		return false
	}
	return !underlayPinnedAtStart
}

func redialDisabledByEnv() bool {
	val := os.Getenv(EnvDisableNetworkChangeRedial)
	if val == "" {
		return false
	}
	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvDisableNetworkChangeRedial, err)
		return false
	}
	return disabled
}
