package internal

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbnet "github.com/netbirdio/netbird/client/net"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
)

// EnvDisableNetworkChangeRedial restores the full client restart on every
// network change, as a field switch should the redial path misbehave.
const EnvDisableNetworkChangeRedial = "NB_DISABLE_NETWORK_CHANGE_REDIAL"

const (
	// controlPlaneSweepGrace lets the sweep (500 ms) close the stale sockets
	// before readiness is checked, so the old connections cannot pass it.
	controlPlaneSweepGrace = 2 * time.Second
	// controlPlaneRecoveryTimeout bounds how long a redial may take before the
	// client falls back to the full restart.
	controlPlaneRecoveryTimeout = 30 * time.Second
	controlPlaneRecoveryPoll    = 500 * time.Millisecond
)

// underlayPinnedAtStart reports the platforms that bind NetBird's own sockets
// to the underlay interface once, at engine start: macOS (scoped default plus
// IP_BOUND_IF) and Windows (IP_UNICAST_IF on the WireGuard socket). Until that
// binding can be refreshed in place, a change there still needs a restart.
const underlayPinnedAtStart = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// underlayAction is what the engine does about one network change.
type underlayAction int

const (
	// actionRestart restarts the client, as every network change did before.
	actionRestart underlayAction = iota
	// actionRedial redials the control connections and keeps the engine up.
	actionRedial
	// actionWait does nothing yet: the network is gone, and the change is
	// handled when it comes back.
	actionWait
)

// recoveryWatch keeps a single safety net running: the latest network change
// replaces the watch of the previous one, so only the latest redial decides
// whether to fall back to a restart.
type recoveryWatch struct {
	cancel context.CancelFunc
}

// redialOnUnderlayChange moves the control connections to the new underlay
// without restarting the client.
func (e *Engine) redialOnUnderlayChange(change networkmonitor.Change) {
	log.Infof("Network monitor: underlay %s change, redialing control connections without restart", change.Kind)
	log.Debugf("Network monitor: underlay next hops v4 %s -> %s, v6 %s -> %s",
		change.Before.V4, change.After.V4, change.Before.V6, change.After.V6)
	e.netMgr.NotifyNetworkChange()
}

func decideUnderlayAction(change networkmonitor.Change, hasNetEvents bool) underlayAction {
	if !canHandleWithoutRestart(change, hasNetEvents) {
		return actionRestart
	}
	if change.Kind == networkmonitor.ChangeOffline {
		return actionWait
	}
	return actionRedial
}

// canHandleWithoutRestart keeps the restart for an unchanged underlay (a flap
// or a wake-up, where the restart is the only recovery today), for legacy
// routing, whose /32 infra routes point at the old gateway, and for platforms
// that pin the underlay at start.
func canHandleWithoutRestart(change networkmonitor.Change, hasNetEvents bool) bool {
	if !hasNetEvents || change.Kind == networkmonitor.ChangeNone || change.Kind == networkmonitor.ChangeWake || redialDisabledByEnv() {
		return false
	}
	if !nbnet.AdvancedRouting() {
		return false
	}
	return !underlayPinnedAtStart
}

func (w *recoveryWatch) replace(parent context.Context) context.Context {
	w.stop()
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	return ctx
}

func (w *recoveryWatch) stop() {
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
}

// watchControlPlaneRecovery is the safety net of the redial path: when
// management, Signal and Relay are not back within controlPlaneRecoveryTimeout,
// it restarts the client as a network change did before.
func (e *Engine) watchControlPlaneRecovery(ctx context.Context, ready func() bool) {
	defer e.shutdownWg.Done()

	if waitUntilReady(ctx, controlPlaneSweepGrace, controlPlaneRecoveryTimeout, controlPlaneRecoveryPoll, ready) {
		log.Infof("Network monitor: control plane is back after the network change")
		return
	}
	if ctx.Err() != nil {
		return
	}
	log.Warnf("Network monitor: control plane not back within %s after the network change, restarting the client", controlPlaneRecoveryTimeout)
	e.triggerClientRestart()
}

// controlPlaneReadiness captures the components at launch, so the check does
// not read engine fields from the watcher goroutine. Relay counts only when
// relay servers are configured.
func controlPlaneReadiness(status *peer.Status, signalClient signal.Client, relayManager *relayClient.Manager) func() bool {
	return func() bool {
		if !status.GetManagementState().Connected {
			return false
		}
		if signalClient != nil && !signalClient.StreamConnected() {
			return false
		}
		if relayManager != nil && relayManager.HasRelayAddress() && !relayManager.Ready() {
			return false
		}
		return true
	}
}

// waitUntilReady waits for grace, then polls ready until it holds. It returns
// false when timeout, counted from the call, elapses first or ctx is done.
func waitUntilReady(ctx context.Context, grace, timeout, poll time.Duration, ready func() bool) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	select {
	case <-time.After(grace):
	case <-deadline.C:
		return false
	case <-ctx.Done():
		return false
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if ready() {
			return true
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			return false
		case <-ctx.Done():
			return false
		}
	}
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
