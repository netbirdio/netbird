package client

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/dnsinterceptor"
	"github.com/netbirdio/netbird/client/internal/routemanager/dynamic"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/static"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

const (
	handlerTypeDynamic = iota
	handlerTypeDnsInterceptor
	handlerTypeStatic
)

const (
	// latencySwitchMinGain is the absolute latency improvement an alternative
	// routing peer must show before an otherwise equivalent current peer is
	// replaced. An absolute margin alone would be meaningless on slow paths,
	// hence latencySwitchGainPercent on top.
	latencySwitchMinGain = 20 * time.Millisecond

	// latencySwitchGainPercent is the relative latency improvement required in
	// addition to latencySwitchMinGain. A relative margin alone would churn on
	// fast paths, where a few milliseconds are a large fraction of the latency.
	latencySwitchGainPercent = 20

	// latencyNoiseSigmas is how many standard deviations of the measurement
	// noise a latency gain has to exceed. Smoothing narrows the scatter of a
	// jittery path but does not remove it, so on such a path two equivalent
	// peers keep producing differences of tens of milliseconds. Requiring the
	// gain to stand out from that scatter is what separates a peer that is
	// really closer from one that only looks closer right now.
	latencyNoiseSigmas = 4

	// latencySwitchMinDwell is how long a routing peer is kept before latency
	// can move the choice again. Changes in connection status, metric or relay
	// state ignore it so failover is never delayed.
	latencySwitchMinDwell = 30 * time.Second

	// routeReevalInterval is how often routes are re-evaluated without an
	// incoming peer state change. A switch deferred by latencySwitchMinDwell,
	// or a latency that drifts in steps too small to notify, would otherwise
	// wait for an unrelated event to be reconsidered.
	routeReevalInterval = latencySwitchMinDwell

	// unknownLatency ranks peers without a latency sample below any peer with a
	// real measurement, without excluding them from selection. It doubles as the
	// upper bound for samples, so a pathological value cannot dominate.
	unknownLatency = 999 * time.Millisecond

	// holdReportInterval is how long a routing peer held back by a switch rule
	// is reported at debug level only, after being reported at info level once.
	holdReportInterval = 10 * time.Minute
)

type reason int

const (
	reasonUnknown reason = iota
	reasonRouteUpdate
	reasonPeerUpdate
	reasonShutdown
	reasonHA
)

// switchReason describes why a routing peer replaced the current one.
type switchReason string

const (
	switchReasonNone         switchReason = ""
	switchReasonUnavailable  switchReason = "current routing peer unavailable"
	switchReasonConnected    switchReason = "connected peer preferred over idle"
	switchReasonMetric       switchReason = "lower route metric"
	switchReasonDirect       switchReason = "direct connection preferred over relayed"
	switchReasonLatency      switchReason = "lower latency"
	switchReasonRouteChanged switchReason = "route assigned to a different routing peer"
)

// holdKind is the rule that keeps the current routing peer over a better one.
type holdKind int

const (
	holdLatencyMargin holdKind = iota
	holdLatencyDwell
	holdRelayedDelay
)

type routerPeerStatus struct {
	status  peer.ConnStatus
	relayed bool
	latency time.Duration
	// noise is the uncertainty of latency, see peer.LatencySample
	noise time.Duration
}

func (s routerPeerStatus) isDirect() bool {
	return s.status == peer.StatusConnected && !s.relayed
}

// routeCandidate is a route considered for selection, together with the
// selection criteria derived from the state of its routing peer.
type routeCandidate struct {
	id        route.ID
	peer      string
	metric    int
	connected bool
	relayed   bool
	latency   time.Duration
	noise     time.Duration
}

func newRouteCandidate(r *route.Route, status routerPeerStatus) routeCandidate {
	latency := status.latency
	if latency <= 0 || latency > unknownLatency {
		latency = unknownLatency
	}

	return routeCandidate{
		id:        r.ID,
		peer:      r.Peer,
		metric:    r.Metric,
		connected: status.status == peer.StatusConnected,
		relayed:   status.relayed,
		latency:   latency,
		noise:     status.noise,
	}
}

// tierCompare orders c against o on the categorical criteria: connection status,
// then route metric, then direct versus relayed. It returns a positive number
// when c outranks o, a negative one when o outranks c, and zero when the two are
// equivalent. Latency is excluded on purpose: it is the tie-break applied by
// betterThan and the only criterion the switch margins in shouldSwitchRoute
// apply to.
func (c routeCandidate) tierCompare(o routeCandidate) int {
	if c.connected != o.connected {
		if c.connected {
			return 1
		}
		return -1
	}
	if c.metric != o.metric {
		return o.metric - c.metric
	}
	if c.relayed != o.relayed {
		if c.relayed {
			return -1
		}
		return 1
	}

	return 0
}

func (c routeCandidate) isDirect() bool {
	return c.connected && !c.relayed
}

func (c routeCandidate) tierBetterThan(o routeCandidate) bool {
	return c.tierCompare(o) > 0
}

// winsOnlyOnRelay reports whether c outranks o solely by being direct while o
// is relayed, with connection status and metric equal.
func (c routeCandidate) winsOnlyOnRelay(o routeCandidate) bool {
	return c.connected == o.connected && c.metric == o.metric && o.relayed && !c.relayed
}

// switchReasonOver names the criterion on which c replaces the current o.
func (c routeCandidate) switchReasonOver(o routeCandidate) switchReason {
	switch {
	case c.connected != o.connected:
		return switchReasonConnected
	case c.metric != o.metric:
		return switchReasonMetric
	case c.relayed != o.relayed:
		return switchReasonDirect
	default:
		return switchReasonLatency
	}
}

func (c routeCandidate) betterThan(o routeCandidate) bool {
	if tier := c.tierCompare(o); tier != 0 {
		return tier > 0
	}

	return c.latency < o.latency
}

func (c routeCandidate) String() string {
	return fmt.Sprintf("connected: %t, metric: %d, relayed: %t, latency: %v +/- %v", c.connected, c.metric, c.relayed, c.latency, c.noise)
}

type RoutesUpdate struct {
	UpdateSerial uint64
	Routes       []*route.Route
}

// RouteHandler defines the interface for handling routes
type RouteHandler interface {
	String() string
	AddRoute(ctx context.Context) error
	RemoveRoute() error
	AddAllowedIPs(peerKey string) error
	RemoveAllowedIPs() error
}

type WatcherConfig struct {
	Context          context.Context
	DNSRouteInterval time.Duration
	WGInterface      iface.WGIface
	StatusRecorder   *peer.Status
	Route            *route.Route
	Handler          RouteHandler
}

// Watcher watches route and peer changes and updates allowed IPs accordingly.
// Once stopped, it cannot be reused.
// The methods are not thread-safe and should be synchronized externally.
type Watcher struct {
	ctx            context.Context
	cancel         context.CancelFunc
	statusRecorder *peer.Status
	wgInterface    iface.WGIface
	routes         map[route.ID]*route.Route
	routeUpdate    chan RoutesUpdate
	// peerStateUpdate holds at most one pending routing peer state notification,
	// see watchPeerStatusChanges
	peerStateUpdate     chan struct{}
	routePeersNotifiers map[string]chan struct{} // map of peer key to channel for peer state changes
	currentChosen       *route.Route
	currentChosenStatus *routerPeerStatus
	// lastSwitch is when currentChosen was last replaced by a latency-driven
	// switch, used to enforce latencySwitchMinDwell. Categorical switches
	// (failover, metric, relay state) leave it untouched: the dwell exists to
	// stop latency ping-pong, and arming it on a failover would delay the
	// return to a recovered better peer.
	lastSwitch time.Time
	// latencySwitch marks the evaluation's switch decision as latency-driven;
	// set by shouldSwitchRoute, consumed when the switch is applied
	latencySwitch bool
	// switchReason describes why the evaluation replaced the current routing
	// peer; set by getBestRouteFromStatuses, consumed when the switch is applied
	switchReason switchReason
	// relayedSwitch is how long a current routing peer that dropped from direct
	// to relayed is kept over an otherwise equivalent direct one. The zero value
	// switches at once.
	relayedSwitch relayedSwitchPolicy
	// trackedCurrent, trackedPeer and trackedDirect are the current route, its
	// routing peer and whether that peer was connected directly as of the
	// previous evaluation, used to tell a peer that dropped to relay while
	// carrying the route from one that was never direct
	trackedCurrent route.ID
	trackedPeer    string
	trackedDirect  bool
	// degradedSince is when the current routing peer dropped from direct to
	// relayed, zero if it is direct or was already relayed when chosen
	degradedSince time.Time
	// relayedHold fires when a relayed switch being held back becomes due, so it
	// is applied on time rather than on the next periodic re-evaluation
	relayedHold *time.Timer
	// heldCandidate and heldKind identify the alternative last held back by the
	// switch rules and the rule holding it, and heldReported is when that was
	// reported at info level. Routes are re-evaluated on every latency change,
	// so a hold is reported once per episode instead of on every evaluation.
	heldCandidate route.ID
	heldKind      holdKind
	heldReported  time.Time
	// reportedUnassigned tracks that the current no-routing-peer episode has
	// been reported, so the periodic re-evaluation does not repeat it
	reportedUnassigned bool
	// done is closed when the Start loop exits, so Stop can wait for it before
	// removing the routes the loop might still be updating
	done chan struct{}
	// lifecycleMu orders Start against Stop: Start runs in its own goroutine
	// and may begin after Stop, or never, so Stop only waits for done when the
	// loop has actually started
	lifecycleMu  sync.Mutex
	started      bool
	stopped      bool
	handler      RouteHandler
	updateSerial uint64
}

func newPeerStateUpdate() chan struct{} {
	return make(chan struct{}, 1)
}

func NewWatcher(config WatcherConfig) *Watcher {
	ctx, cancel := context.WithCancel(config.Context)

	client := &Watcher{
		ctx:                 ctx,
		cancel:              cancel,
		statusRecorder:      config.StatusRecorder,
		wgInterface:         config.WGInterface,
		routes:              make(map[route.ID]*route.Route),
		routePeersNotifiers: make(map[string]chan struct{}),
		routeUpdate:         make(chan RoutesUpdate),
		peerStateUpdate:     newPeerStateUpdate(),
		done:                make(chan struct{}),
		handler:             config.Handler,
		currentChosenStatus: nil,
		relayedSwitch:       relayedSwitch(),
	}
	return client
}

func (w *Watcher) getRouterPeerStatuses() map[route.ID]routerPeerStatus {
	routePeerStatuses := make(map[route.ID]routerPeerStatus)
	for _, r := range w.routes {
		peerStatus, err := w.statusRecorder.GetPeer(r.Peer)
		if err != nil {
			log.Debugf("couldn't fetch peer state %v: %v", r.Peer, err)
			continue
		}
		routePeerStatuses[r.ID] = routerPeerStatus{
			status:  peerStatus.ConnStatus,
			relayed: peerStatus.Relayed,
			latency: peerStatus.Latency,
			noise:   peerStatus.LatencyNoise,
		}
	}
	return routePeerStatuses
}

// getBestRouteFromStatuses determines the most optimal route from the available routes
// within a Watcher, taking into account peer connection status, route metrics, and
// preference for non-relayed and direct connections.
//
// Candidates are ranked by the categorical criteria first, in this order:
// * Connection status: Both connected and idle peers are considered, but connected peers always take precedence.
// * Metric: Routes with lower metrics (better) are prioritized.
// * Non-relayed: Routes without relays are preferred.
// Peers that are equal on all of them are then ranked by latency, lowest first.
//
// Idle peers can still receive allowed IPs to enable lazy connection triggering.
// Connecting peers are skipped: they have no endpoint to assign allowed IPs to.
//
// Replacing the current route is subject to shouldSwitchRoute, so latency alone
// only moves the route when the gain is worth the interruption. In case of a
// tie, the currently active route (if any) is maintained.
//
// It returns the ID of the selected optimal route.
func (w *Watcher) getBestRouteFromStatuses(routePeerStatuses map[route.ID]routerPeerStatus) (route.ID, routerPeerStatus) {
	var currID route.ID
	if w.currentChosen != nil {
		currID = w.currentChosen.ID
	}

	var best, current routeCandidate
	var haveBest, haveCurrent bool

	for _, r := range w.routes {
		peerStatus, found := routePeerStatuses[r.ID]
		// connecting status equals disconnected: no endpoint to assign allowed IPs to
		if !found || peerStatus.status == peer.StatusConnecting {
			continue
		}

		candidate := newRouteCandidate(r, peerStatus)
		if r.ID == currID {
			current, haveCurrent = candidate, true
		}
		if !haveBest || candidate.betterThan(best) {
			best, haveBest = candidate, true
		}
	}

	// Candidates that tie must not displace the current peer: the routes are
	// held in a map, so the winner of a tie would otherwise depend on iteration
	// order and change from one evaluation to the next.
	if haveCurrent && !best.betterThan(current) {
		best = current
	}

	w.trackRelayed(current, haveCurrent)

	if !haveBest {
		w.reportUnassigned()
		w.heldCandidate = ""

		return "", routerPeerStatus{}
	}
	w.reportedUnassigned = false

	if haveCurrent && current.id != best.id {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("best routing peer for [%v] is %s (%s), current is %s (%s)",
				w.handler, best.peer, best, current.peer, current)
		}

		if !w.shouldSwitchRoute(current, best) {
			return current.id, routePeerStatuses[current.id]
		}
	}

	switch {
	case haveCurrent && current.id == best.id:
	case haveCurrent:
		w.switchReason = best.switchReasonOver(current)
		log.Warnf("switching routing peer for network [%v] from %s to %s: %s (%s)",
			w.handler, current.peer, best.peer, w.switchReason, best)
	case w.currentChosen != nil:
		w.switchReason = switchReasonUnavailable
		log.Warnf("switching routing peer for network [%v] from %s to %s: %s (%s)",
			w.handler, w.currentChosen.Peer, best.peer, w.switchReason, best)
	default:
		log.Infof("new chosen route is %s with peer %s for network [%v]: %s",
			best.id, best.peer, w.handler, best)
	}

	return best.id, routePeerStatuses[best.id]
}

// reportUnassigned reports that no routing peer is available for the network,
// once per episode: the periodic re-evaluation would otherwise repeat it for as
// long as the routing peers stay unavailable.
func (w *Watcher) reportUnassigned() {
	if w.reportedUnassigned {
		return
	}
	w.reportedUnassigned = true

	var peers []string
	for _, r := range w.routes {
		peers = append(peers, r.Peer)
	}
	log.Infof("network [%v] has not been assigned a routing peer as no peers from the list %s are currently available", w.handler, peers)
}

// trackRelayed records when the current routing peer dropped from a direct to a
// relayed connection while carrying the route, which starts the relayedSwitch
// delay. A peer that was never direct, because it was relayed when chosen or
// came up over relay from idle, is not degraded: holding on to it would only
// keep the route on the slower path.
func (w *Watcher) trackRelayed(current routeCandidate, haveCurrent bool) {
	if !haveCurrent {
		w.trackedCurrent, w.trackedPeer, w.trackedDirect, w.degradedSince = "", "", false, time.Time{}
		return
	}

	switch {
	case current.id != w.trackedCurrent, current.peer != w.trackedPeer, !current.relayed:
		w.degradedSince = time.Time{}
	case w.trackedDirect:
		w.degradedSince = time.Now()
		// a new degradation, reported as such even if an earlier one held
		// back the same candidate
		w.heldCandidate = ""
	}
	w.trackedCurrent, w.trackedPeer, w.trackedDirect = current.id, current.peer, current.isDirect()
}

// shouldSwitchRoute reports whether the current routing peer should be replaced
// by the candidate, which outranks it.
//
// A candidate that wins on a categorical criterion (it is connected while the
// current peer is not, has a better metric, or is direct while the current peer
// is relayed) takes over immediately. The exception is a current peer that only
// just dropped from direct to relayed, see relayedSwitchDue.
//
// A candidate that only has lower latency has to beat the current peer by the
// switch margin, and the current peer has to have been in place for
// latencySwitchMinDwell. Every switch interrupts the traffic using the route, so
// a gain that is marginal, or that the measurement noise of the two paths can
// account for on its own, is not worth acting on.
//
// An approved latency-driven switch sets w.latencySwitch, which arms the dwell
// time once the switch is applied.
func (w *Watcher) shouldSwitchRoute(current, candidate routeCandidate) bool {
	if candidate.winsOnlyOnRelay(current) {
		return w.relayedSwitchDue(current, candidate)
	}
	if candidate.tierBetterThan(current) {
		return true
	}

	gain := current.latency - candidate.latency
	if margin := switchMargin(current, candidate); gain < margin {
		if level := w.holdLevel(candidate, holdLatencyMargin); log.IsLevelEnabled(level) {
			log.StandardLogger().Logf(level,
				"keeping routing peer %s for [%v] over %s: latency gain %v on %v is below the %v switch margin (%s)",
				current.peer, w.handler, candidate.peer, gain, current.latency, margin, candidate)
		}
		return false
	}

	if dwelled := time.Since(w.lastSwitch); dwelled < latencySwitchMinDwell {
		if level := w.holdLevel(candidate, holdLatencyDwell); log.IsLevelEnabled(level) {
			log.StandardLogger().Logf(level,
				"keeping routing peer %s for [%v] over %s: chosen %v ago, below the %v minimum dwell time",
				current.peer, w.handler, candidate.peer, dwelled.Round(time.Second), latencySwitchMinDwell)
		}
		return false
	}

	w.latencySwitch = true

	return true
}

// relayedSwitchDue reports whether a relayed current routing peer should give
// way to a candidate that is better only by being direct.
//
// A peer that dropped from direct to relayed while carrying the route is kept
// for the relayedSwitch delay: the relay still carries the traffic, staying
// keeps every flow through this routing peer alive, and a direct connection that
// dropped often recovers within seconds. A peer that was already relayed when
// chosen gives way at once, so the route is not stuck on the slower path when a
// direct one becomes available. A switch that is not due yet arms relayedHold so
// it is applied as soon as it becomes due.
func (w *Watcher) relayedSwitchDue(current, candidate routeCandidate) bool {
	if w.degradedSince.IsZero() {
		return true
	}

	policy := w.relayedSwitch
	if !policy.never {
		remaining := policy.delay - time.Since(w.degradedSince)
		if remaining <= 0 {
			return true
		}
		w.armRelayedHold(remaining)
	}

	if level := w.holdLevel(candidate, holdRelayedDelay); log.IsLevelEnabled(level) {
		log.StandardLogger().Logf(level,
			"keeping relayed routing peer %s for [%v] over direct %s: dropped to relay %v ago, switch delay %s",
			current.peer, w.handler, candidate.peer, time.Since(w.degradedSince).Round(time.Second), policy)
	}

	return false
}

func (w *Watcher) armRelayedHold(d time.Duration) {
	if w.relayedHold == nil {
		w.relayedHold = time.NewTimer(d)
		return
	}
	w.relayedHold.Reset(d)
}

// relayedHoldC is the channel of relayedHold, nil while it was never armed so
// that selecting on it blocks.
func (w *Watcher) relayedHoldC() <-chan time.Time {
	if w.relayedHold == nil {
		return nil
	}
	return w.relayedHold.C
}

// holdLevel is the level to report a decision to keep the current routing peer
// at. The first evaluation that holds a given candidate back under a given rule
// is reported at info level, because that is what someone wondering why a route
// did not move needs to see. The repeats stay at debug level for
// holdReportInterval, including when two near-equal peers keep trading places.
func (w *Watcher) holdLevel(candidate routeCandidate, kind holdKind) log.Level {
	if w.heldCandidate == candidate.id && w.heldKind == kind && time.Since(w.heldReported) < holdReportInterval {
		return log.DebugLevel
	}

	w.heldCandidate, w.heldKind, w.heldReported = candidate.id, kind, time.Now()

	return log.InfoLevel
}

// switchMargin is how much lower the candidate's latency has to be before the
// route moves: at least latencySwitchMinGain, at least latencySwitchGainPercent
// of the current latency so the margin scales with slow paths, and more than the
// combined measurement noise of the two paths. The noise term is what keeps a
// jittery path from moving the route on its own; it vanishes on a stable path,
// where the fixed margins decide.
func switchMargin(current, candidate routeCandidate) time.Duration {
	margin := latencySwitchMinGain

	if relative := current.latency * latencySwitchGainPercent / 100; relative > margin {
		margin = relative
	}

	// the two paths vary independently, so their noise adds in quadrature
	noise := time.Duration(latencyNoiseSigmas * math.Hypot(float64(current.noise), float64(candidate.noise)))
	if noise > margin {
		margin = noise
	}

	return margin
}

// watchPeerStatusChanges forwards the state changes of a routing peer to the
// watcher as a notification to re-evaluate. The watcher reads the current peer
// states when it gets to it, so a notification still pending covers any number
// of later changes, and the forwarder never waits for a busy watcher: that
// would stop it draining the subscription and in turn block the peer's updates.
func (w *Watcher) watchPeerStatusChanges(ctx context.Context, peerKey string, peerStateUpdate chan<- struct{}, closer chan struct{}) {
	// the subscription gets its own context so a delivery blocked on it is
	// released as soon as this forwarder exits, not only when the watcher stops
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	subscription := w.statusRecorder.SubscribeToPeerStateChanges(subCtx, peerKey)
	defer w.statusRecorder.UnsubscribePeerStateChanges(subscription)

	for {
		select {
		case <-ctx.Done():
			return
		case <-closer:
			return
		case <-subscription.Events():
			select {
			case peerStateUpdate <- struct{}{}:
				log.Debugf("triggered route state update for Peer: %s", peerKey)
			default:
			}
		}
	}
}

func (w *Watcher) startNewPeerStatusWatchers() {
	for _, r := range w.routes {
		if _, found := w.routePeersNotifiers[r.Peer]; found {
			continue
		}

		closerChan := make(chan struct{})
		w.routePeersNotifiers[r.Peer] = closerChan
		go w.watchPeerStatusChanges(w.ctx, r.Peer, w.peerStateUpdate, closerChan)
	}
}

// addAllowedIPs adds the allowed IPs for the current chosen route to the handler.
func (w *Watcher) addAllowedIPs(route *route.Route) error {
	if err := w.handler.AddAllowedIPs(route.Peer); err != nil {
		return fmt.Errorf("add allowed IPs for peer %s: %w", route.Peer, err)
	}

	if err := w.statusRecorder.AddPeerStateRoute(route.Peer, w.handler.String(), route.GetResourceID()); err != nil {
		log.Warnf("Failed to update peer state: %v", err)
	}

	w.connectEvent(route)
	return nil
}

func (w *Watcher) removeAllowedIPs(route *route.Route, rsn reason) error {
	if err := w.statusRecorder.RemovePeerStateRoute(route.Peer, w.handler.String()); err != nil {
		log.Warnf("Failed to update peer state: %v", err)
	}

	if err := w.handler.RemoveAllowedIPs(); err != nil {
		return fmt.Errorf("remove allowed IPs: %w", err)
	}

	w.disconnectEvent(route, rsn)

	return nil
}

// shouldSkipRecalculation checks if we can skip route recalculation for the same route without status changes
func (w *Watcher) shouldSkipRecalculation(newChosenID route.ID, newStatus routerPeerStatus) bool {
	if w.currentChosen == nil {
		return false
	}

	isSameRoute := w.currentChosen.ID == newChosenID && w.currentChosen.Equal(w.routes[newChosenID])
	if !isSameRoute {
		return false
	}

	if w.currentChosenStatus != nil {
		return w.currentChosenStatus.status == newStatus.status
	}

	return true
}

func (w *Watcher) recalculateRoutes(rsn reason, routerPeerStatuses map[route.ID]routerPeerStatus) error {
	w.latencySwitch = false
	w.switchReason = switchReasonNone
	newChosenID, newStatus := w.getBestRouteFromStatuses(routerPeerStatuses)

	// If no route is chosen, remove the route from the peer
	if newChosenID == "" {
		if w.currentChosen == nil {
			return nil
		}

		if err := w.removeAllowedIPs(w.currentChosen, rsn); err != nil {
			return fmt.Errorf("remove obsolete: %w", err)
		}
		if rsn == reasonPeerUpdate {
			w.routingPeerLostEvent(w.currentChosen)
		}

		w.currentChosen = nil
		w.currentChosenStatus = nil

		return nil
	}

	// If we can skip recalculation for the same route without changes, do nothing
	if w.shouldSkipRecalculation(newChosenID, newStatus) {
		return nil
	}

	previous := w.currentChosen
	newChosenRoute := w.routes[newChosenID]
	// a route update can hand the same route to a different routing peer
	peerReplaced := previous != nil && previous.ID == newChosenID && previous.Peer != newChosenRoute.Peer
	switched := previous == nil || previous.ID != newChosenID || peerReplaced
	if peerReplaced {
		w.switchReason = switchReasonRouteChanged
		log.Warnf("switching routing peer for network [%v] from %s to %s: %s",
			w.handler, previous.Peer, newChosenRoute.Peer, w.switchReason)
	}

	// If the chosen route was assigned to a different peer, remove the allowed IPs first
	if isNew := w.currentChosen == nil; !isNew {
		if err := w.removeAllowedIPs(w.currentChosen, reasonHA); err != nil {
			return fmt.Errorf("remove old: %w", err)
		}
	}

	if err := w.addAllowedIPs(newChosenRoute); err != nil {
		return fmt.Errorf("add new: %w", err)
	}
	if newStatus.status != peer.StatusIdle {
		w.connectEvent(newChosenRoute)
	}

	w.currentChosen = newChosenRoute
	w.currentChosenStatus = &newStatus
	if !switched {
		return nil
	}

	// start tracking the new routing peer from the state it was chosen in, so a
	// drop to relay seen by the next evaluation counts as a degradation
	w.trackedCurrent, w.trackedPeer = newChosenID, newChosenRoute.Peer
	w.trackedDirect, w.degradedSince = newStatus.isDirect(), time.Time{}
	if w.latencySwitch {
		w.lastSwitch = time.Now()
	}
	if previous != nil {
		w.routingPeerSwitchEvent(previous, newChosenRoute)
	}

	return nil
}

// routingPeerSwitchEvent publishes a replaced routing peer as a system event,
// so it shows in the status output and debug bundles whatever the log level.
// Moving a masqueraded route resets the connections that used it. For default
// routes this adds the reason to the events of disconnectEvent and
// connectEvent, and carries no user message so it is not shown as a
// notification a second time.
func (w *Watcher) routingPeerSwitchEvent(previous, next *route.Route) {
	if w.statusRecorder == nil {
		return
	}

	reason := w.switchReason
	if reason == switchReasonNone {
		reason = switchReasonUnavailable
	}

	w.statusRecorder.PublishEvent(
		proto.SystemEvent_WARNING,
		proto.SystemEvent_NETWORK,
		"Routing peer changed",
		"",
		map[string]string{
			"network":       w.handler.String(),
			"id":            string(next.NetID),
			"previous_peer": previous.Peer,
			"peer":          next.Peer,
			"reason":        string(reason),
		},
	)
}

// routingPeerLostEvent publishes the loss of the last available routing peer of
// a network as a system event. Default routes are left to disconnectEvent.
func (w *Watcher) routingPeerLostEvent(previous *route.Route) {
	if w.statusRecorder == nil || w.hasDefaultRoute() {
		return
	}

	w.statusRecorder.PublishEvent(
		proto.SystemEvent_WARNING,
		proto.SystemEvent_NETWORK,
		"No routing peer available",
		"",
		map[string]string{
			"network":       w.handler.String(),
			"id":            string(previous.NetID),
			"previous_peer": previous.Peer,
		},
	)
}

func (w *Watcher) hasDefaultRoute() bool {
	for _, r := range w.routes {
		if r.Network.Bits() == 0 {
			return true
		}
	}
	return false
}

func (w *Watcher) connectEvent(route *route.Route) {
	if !w.hasDefaultRoute() {
		return
	}

	meta := map[string]string{
		"network": w.handler.String(),
	}
	if route != nil {
		meta["id"] = string(route.NetID)
		meta["peer"] = route.Peer
	}
	w.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_NETWORK,
		"Default route added",
		"Exit node connected.",
		meta,
	)
}

func (w *Watcher) disconnectEvent(route *route.Route, rsn reason) {
	if !w.hasDefaultRoute() {
		return
	}

	var severity proto.SystemEvent_Severity
	var message string
	var userMessage string
	meta := make(map[string]string)

	if route != nil {
		meta["id"] = string(route.NetID)
		meta["peer"] = route.Peer
	}
	meta["network"] = w.handler.String()
	switch rsn {
	case reasonShutdown:
		severity = proto.SystemEvent_INFO
		message = "Default route removed"
		userMessage = "Exit node disconnected."
	case reasonRouteUpdate:
		severity = proto.SystemEvent_INFO
		message = "Default route updated due to configuration change"
	case reasonPeerUpdate:
		severity = proto.SystemEvent_WARNING
		message = "Default route disconnected due to peer unreachability"
		userMessage = "Exit node connection lost. Your internet access might be affected."
	case reasonHA:
		severity = proto.SystemEvent_INFO
		message = "Default route disconnected due to high availability change"
		userMessage = "Exit node disconnected due to high availability change."
	default:
		severity = proto.SystemEvent_ERROR
		message = "Default route disconnected for unknown reasons"
		userMessage = "Exit node disconnected for unknown reasons."
	}

	w.statusRecorder.PublishEvent(
		severity,
		proto.SystemEvent_NETWORK,
		message,
		userMessage,
		meta,
	)
}

func (w *Watcher) SendUpdate(update RoutesUpdate) {
	go func() {
		select {
		case w.routeUpdate <- update:
		case <-w.ctx.Done():
		}
	}()
}

func (w *Watcher) classifyUpdate(update RoutesUpdate) bool {
	isUpdateMapDifferent := false
	updateMap := make(map[route.ID]*route.Route)

	for _, r := range update.Routes {
		updateMap[r.ID] = r
	}

	if len(w.routes) != len(updateMap) {
		isUpdateMapDifferent = true
	}

	for id, r := range w.routes {
		_, found := updateMap[id]
		if !found {
			close(w.routePeersNotifiers[r.Peer])
			delete(w.routePeersNotifiers, r.Peer)
			isUpdateMapDifferent = true
			continue
		}
		if !reflect.DeepEqual(w.routes[id], updateMap[id]) {
			isUpdateMapDifferent = true
		}
	}

	w.routes = updateMap
	return isUpdateMapDifferent
}

// Start is the main point of reacting on client network routing events.
// All the processing related to the client network should be done here. Thread-safe.
func (w *Watcher) Start() {
	w.lifecycleMu.Lock()
	if w.stopped || w.started {
		w.lifecycleMu.Unlock()
		return
	}
	w.started = true
	w.lifecycleMu.Unlock()

	defer close(w.done)

	reeval := time.NewTicker(routeReevalInterval)
	defer reeval.Stop()
	defer func() {
		if w.relayedHold != nil {
			w.relayedHold.Stop()
		}
	}()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-reeval.C:
			if err := w.recalculateRoutes(reasonPeerUpdate, w.getRouterPeerStatuses()); err != nil {
				log.Errorf("Failed to re-evaluate routes for network [%v]: %v", w.handler, err)
			}
		case <-w.relayedHoldC():
			if err := w.recalculateRoutes(reasonPeerUpdate, w.getRouterPeerStatuses()); err != nil {
				log.Errorf("Failed to re-evaluate routes for network [%v]: %v", w.handler, err)
			}
		case <-w.peerStateUpdate:
			// The notification only says that a routing peer changed. The states it
			// carries can be older than ones already applied, since every routing
			// peer has its own subscription, so the current states are read instead.
			if err := w.recalculateRoutes(reasonPeerUpdate, w.getRouterPeerStatuses()); err != nil {
				log.Errorf("Failed to recalculate routes for network [%v]: %v", w.handler, err)
			}
		case update := <-w.routeUpdate:
			if update.UpdateSerial < w.updateSerial {
				log.Warnf("Received a routes update with smaller serial number (%d -> %d), ignoring it", w.updateSerial, update.UpdateSerial)
				continue
			}

			w.handleRouteUpdate(update)
		}
	}
}

func (w *Watcher) handleRouteUpdate(update RoutesUpdate) {
	log.Debugf("Received a new client network route update for [%v]", w.handler)

	// hash update somehow
	isTrueRouteUpdate := w.classifyUpdate(update)

	w.updateSerial = update.UpdateSerial

	if isTrueRouteUpdate {
		log.Debugf("client network update %v for [%v] contains different routes, recalculating routes", update.UpdateSerial, w.handler)
		routePeerStatuses := w.getRouterPeerStatuses()
		if err := w.recalculateRoutes(reasonRouteUpdate, routePeerStatuses); err != nil {
			log.Errorf("failed to recalculate routes for network [%v]: %v", w.handler, err)
		}
	} else {
		log.Debugf("route update %v for [%v] is not different, skipping route recalculation", update.UpdateSerial, w.handler)
	}

	w.startNewPeerStatusWatchers()
}

// Stop stops the watcher and cleans up resources.
func (w *Watcher) Stop() {
	log.Debugf("Stopping watcher for network [%v]", w.handler)

	w.lifecycleMu.Lock()
	if w.stopped {
		w.lifecycleMu.Unlock()
		return
	}
	w.stopped = true
	started := w.started
	w.lifecycleMu.Unlock()

	w.cancel()
	// wait for the Start loop to exit: it may be inside a recalculation, and
	// cleaning up concurrently would race on currentChosen and could leave the
	// allowed IPs of a route chosen after this point behind
	if started {
		<-w.done
	}

	if w.currentChosen == nil {
		return
	}
	if err := w.removeAllowedIPs(w.currentChosen, reasonShutdown); err != nil {
		log.Errorf("Failed to remove routes for [%v]: %v", w.handler, err)
	}
	w.currentChosenStatus = nil
}

func HandlerFromRoute(params common.HandlerParams) RouteHandler {
	switch handlerType(params.Route, params.UseNewDNSRoute) {
	case handlerTypeDnsInterceptor:
		return dnsinterceptor.New(params)
	case handlerTypeDynamic:
		dns := nbdns.NewServiceViaMemory(params.WgInterface)
		dnsAddr := netip.AddrPortFrom(dns.RuntimeIP(), uint16(dns.RuntimePort()))
		return dynamic.NewRoute(params, dnsAddr)
	default:
		return static.NewRoute(params)
	}
}

func handlerType(rt *route.Route, useNewDNSRoute bool) int {
	if !rt.IsDynamic() {
		return handlerTypeStatic
	}

	if useNewDNSRoute {
		return handlerTypeDnsInterceptor
	}
	return handlerTypeDynamic
}
