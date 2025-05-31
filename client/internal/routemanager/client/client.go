package client

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/dnsinterceptor"
	"github.com/netbirdio/netbird/client/internal/routemanager/dynamic"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/static"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

const (
	handlerTypeDynamic = iota
	handlerTypeDomain
	handlerTypeStatic
)

type reason int

const (
	reasonUnknown reason = iota
	reasonRouteUpdate
	reasonPeerUpdate
	reasonShutdown
	reasonHA
)

type routerPeerStatus struct {
	connected bool
	relayed   bool
	latency   time.Duration
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
type Watcher struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	statusRecorder      *peer.Status
	wgInterface         iface.WGIface
	routes              map[route.ID]*route.Route
	routeUpdate         chan RoutesUpdate
	peerStateUpdate     chan struct{}
	routePeersNotifiers map[string]chan struct{} // map of peer key to channel for peer state changes
	currentChosen       *route.Route
	handler             RouteHandler
	updateSerial        uint64
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
		peerStateUpdate:     make(chan struct{}),
		handler:             config.Handler,
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
			connected: peerStatus.ConnStatus == peer.StatusConnected,
			relayed:   peerStatus.Relayed,
			latency:   peerStatus.Latency,
		}
	}
	return routePeerStatuses
}

// getBestRouteFromStatuses determines the most optimal route from the available routes
// within a Watcher, taking into account peer connection status, route metrics, and
// preference for non-relayed and direct connections.
//
// It follows these prioritization rules:
// * Connected peers: Only routes with connected peers are considered.
// * Metric: Routes with lower metrics (better) are prioritized.
// * Non-relayed: Routes without relays are preferred.
// * Latency: Routes with lower latency are prioritized.
// * we compare the current score + 10ms to the chosen score to avoid flapping between routes
// * Stability: In case of equal scores, the currently active route (if any) is maintained.
//
// It returns the ID of the selected optimal route.
func (w *Watcher) getBestRouteFromStatuses(routePeerStatuses map[route.ID]routerPeerStatus) route.ID {
	var chosen route.ID
	chosenScore := float64(0)
	currScore := float64(0)

	var currID route.ID
	if w.currentChosen != nil {
		currID = w.currentChosen.ID
	}

	for _, r := range w.routes {
		tempScore := float64(0)
		peerStatus, found := routePeerStatuses[r.ID]
		if !found || !peerStatus.connected {
			continue
		}

		if r.Metric < route.MaxMetric {
			metricDiff := route.MaxMetric - r.Metric
			tempScore = float64(metricDiff) * 10
		}

		// in some temporal cases, latency can be 0, so we set it to 999ms to not block but try to avoid this route
		latency := 999 * time.Millisecond
		if peerStatus.latency != 0 {
			latency = peerStatus.latency
		} else {
			log.Tracef("peer %s has 0 latency, range %s", r.Peer, w.handler)
		}

		// avoid negative tempScore on the higher latency calculation
		if latency > 1*time.Second {
			latency = 999 * time.Millisecond
		}

		// higher latency is worse score
		tempScore += 1 - latency.Seconds()

		if !peerStatus.relayed {
			tempScore++
		}

		if tempScore > chosenScore || (tempScore == chosenScore && chosen == "") {
			chosen = r.ID
			chosenScore = tempScore
		}

		if chosen == "" && currID == "" {
			chosen = r.ID
			chosenScore = tempScore
		}

		if r.ID == currID {
			currScore = tempScore
		}
	}

	chosenID := chosen
	if chosen == "" {
		chosenID = "<none>"
	}
	currentID := currID
	if currID == "" {
		currentID = "<none>"
	}

	log.Debugf("chosen route: %s, chosen score: %f, current route: %s, current score: %f", chosenID, chosenScore, currentID, currScore)

	switch {
	case chosen == "":
		var peers []string
		for _, r := range w.routes {
			peers = append(peers, r.Peer)
		}

		log.Infof("network [%v] has not been assigned a routing peer as no peers from the list %s are currently connected", w.handler, peers)
	case chosen != currID:
		// we compare the current score + 10ms to the chosen score to avoid flapping between routes
		if currScore != 0 && currScore+0.01 > chosenScore {
			log.Debugf("keeping current routing peer %s for [%v]: the score difference with latency is less than 0.01(10ms): current: %f, new: %f",
				w.currentChosen.Peer, w.handler, currScore, chosenScore)
			return currID
		}
		var p string
		if rt := w.routes[chosen]; rt != nil {
			p = rt.Peer
		}
		log.Infof("New chosen route is %s with peer %s with score %f for network [%v]", chosen, p, chosenScore, w.handler)
	}

	return chosen
}

func (w *Watcher) watchPeerStatusChanges(ctx context.Context, peerKey string, peerStateUpdate chan struct{}, closer chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-closer:
			return
		case <-w.statusRecorder.GetPeerStateChangeNotifier(peerKey):
			state, err := w.statusRecorder.GetPeer(peerKey)
			if err != nil {
				continue
			}
			peerStateUpdate <- struct{}{}
			log.Debugf("triggered route state update for Peer %s, state: %s", peerKey, state.ConnStatus)
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

func (w *Watcher) recalculateRoutes(rsn reason) error {
	routerPeerStatuses := w.getRouterPeerStatuses()

	newChosenID := w.getBestRouteFromStatuses(routerPeerStatuses)

	// If no route is chosen, remove the route from the peer
	if newChosenID == "" {
		if w.currentChosen == nil {
			return nil
		}

		if err := w.removeAllowedIPs(w.currentChosen, rsn); err != nil {
			return fmt.Errorf("remove obsolete: %w", err)
		}

		w.currentChosen = nil

		return nil
	}

	// If the chosen route is the same as the current route, do nothing
	if w.currentChosen != nil && w.currentChosen.ID == newChosenID &&
		w.currentChosen.Equal(w.routes[newChosenID]) {
		return nil
	}

	// If the chosen route was assigned to a different peer, remove the allowed IPs first
	if isNew := w.currentChosen == nil; !isNew {
		if err := w.removeAllowedIPs(w.currentChosen, reasonHA); err != nil {
			return fmt.Errorf("remove old: %w", err)
		}
	}

	newChosenRoute := w.routes[newChosenID]
	if err := w.addAllowedIPs(newChosenRoute); err != nil {
		return fmt.Errorf("add new: %w", err)
	}

	w.currentChosen = newChosenRoute

	return nil
}

func (w *Watcher) connectEvent(route *route.Route) {
	var defaultRoute bool
	for _, r := range w.routes {
		if r.Network.Bits() == 0 {
			defaultRoute = true
			break
		}
	}

	if !defaultRoute {
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
	var defaultRoute bool
	for _, r := range w.routes {
		if r.Network.Bits() == 0 {
			defaultRoute = true
			break
		}
	}

	if !defaultRoute {
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
		w.routeUpdate <- update
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
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.peerStateUpdate:
			if err := w.recalculateRoutes(reasonPeerUpdate); err != nil {
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
		if err := w.recalculateRoutes(reasonRouteUpdate); err != nil {
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

	w.cancel()

	if err := w.removeAllowedIPs(w.currentChosen, reasonShutdown); err != nil {
		log.Errorf("Failed to remove routes for [%v]: %v", w.handler, err)
	}
}

func HandlerFromRoute(
	rt *route.Route,
	routeRefCounter *refcounter.RouteRefCounter,
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter,
	dnsRouterInteval time.Duration,
	statusRecorder *peer.Status,
	wgInterface iface.WGIface,
	dnsServer nbdns.Server,
	peerStore *peerstore.Store,
	useNewDNSRoute bool,
) RouteHandler {
	switch handlerType(rt, useNewDNSRoute) {
	case handlerTypeDomain:
		return dnsinterceptor.New(
			rt,
			routeRefCounter,
			allowedIPsRefCounter,
			statusRecorder,
			dnsServer,
			peerStore,
		)
	case handlerTypeDynamic:
		dns := nbdns.NewServiceViaMemory(wgInterface)
		return dynamic.NewRoute(
			rt,
			routeRefCounter,
			allowedIPsRefCounter,
			dnsRouterInteval,
			statusRecorder,
			wgInterface,
			fmt.Sprintf("%s:%d", dns.RuntimeIP(), dns.RuntimePort()),
		)
	default:
		return static.NewRoute(rt, routeRefCounter, allowedIPsRefCounter)
	}
}

func handlerType(rt *route.Route, useNewDNSRoute bool) int {
	if !rt.IsDynamic() {
		return handlerTypeStatic
	}

	if useNewDNSRoute && runtime.GOOS != "ios" {
		return handlerTypeDomain
	}
	return handlerTypeDynamic
}
