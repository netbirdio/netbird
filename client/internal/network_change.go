package internal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	nbnetstack "github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/netevents"
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

// wgSocketPinned reports the platforms that bind the WireGuard UDP socket to
// the underlay interface when it opens (IP_UNICAST_IF on Windows, IP_BOUND_IF
// on macOS), so the socket must be reopened when the interface changes.
const wgSocketPinned = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

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
	// actionNone does nothing: nothing NetBird depends on moved. What the
	// snapshot cannot see is left to the control connections' own retries and
	// to the safety net of the next redial.
	actionNone
)

// underlayLoop turns the network monitor's changes into engine actions. Its
// steps are injected so the sequence can be tested without an engine; all of
// them run on the loop's goroutine.
type underlayLoop struct {
	listen       func(context.Context, networkmonitor.NextHops) (networkmonitor.Change, error)
	decide       func(networkmonitor.Change) underlayAction
	redial       func(networkmonitor.Change) bool
	restart      func()
	armWatch     func()
	stopWatch    func()
	availability networkAvailability
}

func (l *underlayLoop) run(ctx context.Context) {
	defer l.stopWatch()
	// The manager outlives this engine: never leave it offline.
	defer l.availability.set(true)
	// baseline is the last snapshot with a default route; it survives an
	// offline spell so the change is measured against the network before it.
	var baseline networkmonitor.NextHops
	offline := false
	for {
		change, err := l.listen(ctx, baseline)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				log.Infof("network monitor stopped")
				return
			}
			log.Errorf("network monitor error: %v", err)
			return
		}

		action := l.decide(change)
		l.availability.set(action != actionWait)
		returning := offline && action != actionWait
		offline = action == actionWait
		switch action {
		case actionWait:
			log.Infof("Network monitor: no default route left, waiting for the network to come back")
			// Offline the control plane cannot come back: a running safety
			// net would restart into the leak. The next redial arms a new one.
			l.stopWatch()
			baseline = change.Before
			continue
		case actionNone:
			log.Infof("Network monitor: route event without any underlay change, nothing to do")
			// Going offline swept the control connections: watch them come
			// back even though the network is the one from before.
			if returning {
				l.armWatch()
			}
			baseline = change.After
			continue
		case actionRedial:
			if !l.redial(change) {
				break
			}
			l.armWatch()
			baseline = change.After
			continue
		}

		log.Infof("Network monitor: detected network change (%s), triggering client restart", change.Kind)
		l.restart()
		return
	}
}

// networkAvailability reports the network state to the netevents manager on
// desktop, where no OS callback does it: offline holds the reconnect loops
// and shows the client as without network instead of connected.
type networkAvailability struct {
	mgr     *netevents.Manager
	offline bool
}

// set reports a change of availability; repeats are dropped.
func (a *networkAvailability) set(available bool) {
	if a.mgr == nil || a.offline == !available {
		return
	}
	a.offline = !available
	a.mgr.SetNetworkAvailable(available)
}

// recoveryWatch keeps a single safety net running: the latest network change
// replaces the watch of the previous one, so only the latest redial decides
// whether to fall back to a restart.
type recoveryWatch struct {
	cancel context.CancelFunc
}

// redialOnUnderlayChange moves the control connections to the new underlay
// without restarting the client.
// It returns false when the change could not be handled in place and only a
// restart can recover.
func (e *Engine) redialOnUnderlayChange(change networkmonitor.Change) bool {
	// The engine may be stopping: there is nothing left to move, and its
	// teardown must not race with the steps below.
	if e.ctx.Err() != nil {
		return true
	}
	log.Infof("Network monitor: underlay %s change, redialing control connections without restart", change.Kind)
	log.Debugf("Network monitor: underlay next hops v4 %s -> %s, v6 %s -> %s",
		change.Before.V4, change.After.V4, change.Before.V6, change.After.V6)

	// Point NetBird's own traffic at the new physical default first, so the
	// reopened WireGuard socket and the redialed connections bind to it.
	if change.Kind == networkmonitor.ChangeInterface || change.Kind == networkmonitor.ChangeGateway {
		if err := e.routeManager.RefreshUnderlay(); err != nil {
			log.Warnf("Network monitor: failed to refresh the underlay binding: %v", err)
			return false
		}
	}

	rebound := false
	if wgSocketPinned && change.Kind == networkmonitor.ChangeInterface {
		if err := e.rebindWGSocket(); err != nil {
			log.Warnf("Network monitor: failed to reopen the WireGuard socket on the new interface: %v", err)
			return false
		}
		rebound = true
	}

	e.netMgr.NotifyNetworkChange()
	e.moveP2PPeersToRelay(rebound)
	return true
}

// rebindWGSocket reopens the userspace WireGuard socket, on the same port, so
// it binds to the interface that now holds the default route. Kernel
// WireGuard has no such socket to reopen.
func (e *Engine) rebindWGSocket() error {
	// The lock-free handle: going through wgInterface needs syncMsgMux, and
	// the engine's teardown clears both.
	dev := e.wgDevice.Load()
	if dev == nil {
		return nil
	}
	log.Infof("Network monitor: interface changed, reopening the WireGuard socket")
	return dev.BindUpdate()
}

// moveP2PPeersToRelay makes relay the active path of every P2P peer whose
// path did not survive the change and renegotiates P2P on the new network, so
// traffic does not wait for the ICE timeouts on a dead path. After the
// WireGuard socket was reopened every P2P path is gone, whatever its
// candidate.
func (e *Engine) moveP2PPeersToRelay(socketReopened bool) {
	hostAddrs := currentHostAddrs()
	localAddrExists := func(addr netip.Addr) bool {
		if socketReopened {
			return false
		}
		_, ok := hostAddrs[addr]
		return ok
	}
	for _, key := range e.peerStore.PeersPubKey() {
		if conn, ok := e.peerStore.PeerConn(key); ok {
			conn.OnUnderlayChanged(localAddrExists)
		}
	}
}

// currentHostAddrs returns every address configured on the host right now.
func currentHostAddrs() map[netip.Addr]struct{} {
	addrs := make(map[netip.Addr]struct{})
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Debugf("Network monitor: failed to read host addresses: %v", err)
		return addrs
	}
	for _, a := range ifAddrs {
		if prefix, err := netip.ParsePrefix(a.String()); err == nil {
			addrs[prefix.Addr().Unmap()] = struct{}{}
		}
	}
	return addrs
}

func decideUnderlayAction(change networkmonitor.Change, hasNetEvents bool) underlayAction {
	if !canHandleWithoutRestart(change, hasNetEvents) {
		return actionRestart
	}
	switch change.Kind {
	case networkmonitor.ChangeOffline:
		return actionWait
	case networkmonitor.ChangeNone:
		return actionNone
	default:
		return actionRedial
	}
}

// canHandleWithoutRestart keeps the restart for a wake-up, out of scope and
// still covered by the restart, and for legacy routing, whose /32 infra routes
// point at the old gateway.
func canHandleWithoutRestart(change networkmonitor.Change, hasNetEvents bool) bool {
	if !hasNetEvents || change.Kind == networkmonitor.ChangeWake || redialDisabledByEnv() {
		return false
	}
	return nbnet.AdvancedRouting()
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

// NetEventsFor returns events when the desktop network change handling will
// use them: the network monitor runs, routing is advanced and the redial is
// not disabled. Otherwise it returns nil, so the relay, management and Signal
// clients keep the reconnect behavior they have without OS network events,
// and NB_DISABLE_NETWORK_CHANGE_REDIAL restores the old client as a whole.
func NetEventsFor(config *profilemanager.Config, events *netevents.Manager) *netevents.Manager {
	monitor := config.NetworkMonitor != nil && *config.NetworkMonitor && !nbnetstack.IsEnabled()
	if !monitor || !nbnet.AdvancedRouting() || redialDisabledByEnv() {
		return nil
	}
	return events
}
