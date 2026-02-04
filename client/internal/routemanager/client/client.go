package client

import (
	"context"
	"fmt"
	"reflect"
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

type reason int

const (
	reasonUnknown reason = iota
	reasonRouteUpdate
	reasonPeerUpdate
	reasonShutdown
	reasonHA
)

type routerPeerStatus struct {
	status  peer.ConnStatus
	relayed bool
	latency time.Duration
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
	ctx                 context.Context
	cancel              context.CancelFunc
	statusRecorder      *peer.Status
	wgInterface         iface.WGIface
	routes              map[route.ID]*route.Route
	routeUpdate         chan RoutesUpdate
	peerStateUpdate     chan map[string]peer.RouterState
	routePeersNotifiers map[string]chan struct{} // map of peer key to channel for peer state changes
	currentChosen       *route.Route
	currentChosenStatus *routerPeerStatus
	handler             RouteHandler
	updateSerial        uint64
}

func NewWatcher(config WatcherConfig) *Watcher {
	ctx, cancel := context.WithCancel(config.Context)

	log.Warnf("[DNS-ROUTE] NewWatcher: creating watcher for handler=%s route=%s", config.Handler.String(), config.Route.Network)

	client := &Watcher{
		ctx:                 ctx,
		cancel:              cancel,
		statusRecorder:      config.StatusRecorder,
		wgInterface:         config.WGInterface,
		routes:              make(map[route.ID]*route.Route),
		routePeersNotifiers: make(map[string]chan struct{}),
		routeUpdate:         make(chan RoutesUpdate),
		peerStateUpdate:     make(chan map[string]peer.RouterState),
		handler:             config.Handler,
		currentChosenStatus: nil,
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
		}
	}
	return routePeerStatuses
}

func (w *Watcher) convertRouterPeerStatuses(states map[string]peer.RouterState) map[route.ID]routerPeerStatus {
	routePeerStatuses := make(map[route.ID]routerPeerStatus)
	for _, r := range w.routes {
		peerStatus, ok := states[r.Peer]
		if !ok {
			log.Warnf("couldn't fetch peer state: %v", r.Peer)
			continue
		}
		routePeerStatuses[r.ID] = routerPeerStatus{
			status:  peerStatus.Status,
			relayed: peerStatus.Relayed,
			latency: peerStatus.Latency,
		}
	}
	return routePeerStatuses
}

// getBestRouteFromStatuses determines the most optimal route from the available routes
// within a Watcher, taking into account peer connection status, route metrics, and
// preference for non-relayed and direct connections.
//
// It follows these prioritization rules:
// * Connection status: Both connected and idle peers are considered, but connected peers always take precedence.
// * Idle peer penalty: Idle peers receive a significant score penalty to ensure any connected peer is preferred.
// * Metric: Routes with lower metrics (better) are prioritized.
// * Non-relayed: Routes without relays are preferred.
// * Latency: Routes with lower latency are prioritized.
// * Allowed IPs: Idle peers can still receive allowed IPs to enable lazy connection triggering.
// * we compare the current score + 10ms to the chosen score to avoid flapping between routes
// * Stability: In case of equal scores, the currently active route (if any) is maintained.
//
// It returns the ID of the selected optimal route.
func (w *Watcher) getBestRouteFromStatuses(routePeerStatuses map[route.ID]routerPeerStatus) (route.ID, routerPeerStatus) {
	var chosen route.ID
	chosenScore := float64(0)
	currScore := float64(0)

	var currID route.ID
	if w.currentChosen != nil {
		currID = w.currentChosen.ID
	}

	var chosenStatus routerPeerStatus

	for _, r := range w.routes {
		tempScore := float64(0)
		peerStatus, found := routePeerStatuses[r.ID]
		// connecting status equals disconnected: no wireguard endpoint to assign allowed IPs to
		if !found || peerStatus.status == peer.StatusConnecting {
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
		} else if !peerStatus.relayed && peerStatus.status != peer.StatusIdle {
			log.Tracef("peer %s has 0 latency: [%v]", r.Peer, w.handler)
		}

		// avoid negative tempScore on the higher latency calculation
		if latency > 1*time.Second {
			latency = 999 * time.Millisecond
		}

		// higher latency is worse score
		tempScore += 1 - latency.Seconds()

		// apply significant penalty for idle peers to ensure connected peers always take precedence
		if peerStatus.status == peer.StatusConnected {
			tempScore += 100_000
		}

		if !peerStatus.relayed {
			tempScore++
		}

		if tempScore > chosenScore || (tempScore == chosenScore && chosen == "") {
			chosen = r.ID
			chosenStatus = peerStatus
			chosenScore = tempScore
		}

		if chosen == "" && currID == "" {
			chosen = r.ID
			chosenStatus = peerStatus
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

		log.Infof("network [%v] has not been assigned a routing peer as no peers from the list %s are currently available", w.handler, peers)
	case chosen != currID:
		// we compare the current score + 10ms to the chosen score to avoid flapping between routes
		if currScore != 0 && currScore+0.01 > chosenScore {
			log.Debugf("keeping current routing peer %s for [%v]: the score difference with latency is less than 0.01(10ms): current: %f, new: %f",
				w.currentChosen.Peer, w.handler, currScore, chosenScore)
			return currID, chosenStatus
		}
		var p string
		if rt := w.routes[chosen]; rt != nil {
			p = rt.Peer
		}
		log.Infof("New chosen route is %s with peer %s with score %f for network [%v]", chosen, p, chosenScore, w.handler)
	}

	return chosen, chosenStatus
}

func (w *Watcher) watchPeerStatusChanges(ctx context.Context, peerKey string, peerStateUpdate chan map[string]peer.RouterState, closer chan struct{}) {
	subscription := w.statusRecorder.SubscribeToPeerStateChanges(ctx, peerKey)
	defer w.statusRecorder.UnsubscribePeerStateChanges(subscription)

	for {
		select {
		case <-ctx.Done():
			return
		case <-closer:
			return
		case routerStates := <-subscription.Events():
			peerStateUpdate <- routerStates
			log.Debugf("triggered route state update for Peer: %s", peerKey)
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
	log.Warnf("[DNS-ROUTE] Watcher.addAllowedIPs: handler=%s peer=%s network=%s", w.handler.String(), route.Peer, route.Network)

	if err := w.handler.AddAllowedIPs(route.Peer); err != nil {
		log.Warnf("[DNS-ROUTE] Watcher.addAllowedIPs: failed handler=%s peer=%s: %v", w.handler.String(), route.Peer, err)
		return fmt.Errorf("add allowed IPs for peer %s: %w", route.Peer, err)
	}

	log.Warnf("[DNS-ROUTE] Watcher.addAllowedIPs: success handler=%s peer=%s", w.handler.String(), route.Peer)

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
	log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s reason=%d peerStatuses=%d currentChosen=%v",
		w.handler.String(), rsn, len(routerPeerStatuses), w.currentChosen != nil)

	newChosenID, newStatus := w.getBestRouteFromStatuses(routerPeerStatuses)
	log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s newChosenID=%s newStatus=%+v",
		w.handler.String(), newChosenID, newStatus)

	// If no route is chosen, remove the route from the peer
	if newChosenID == "" {
		if w.currentChosen == nil {
			log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s no route chosen and no current, nothing to do", w.handler.String())
			return nil
		}

		log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s removing obsolete route", w.handler.String())
		if err := w.removeAllowedIPs(w.currentChosen, rsn); err != nil {
			return fmt.Errorf("remove obsolete: %w", err)
		}

		w.currentChosen = nil
		w.currentChosenStatus = nil

		return nil
	}

	// If we can skip recalculation for the same route without changes, do nothing
	if w.shouldSkipRecalculation(newChosenID, newStatus) {
		log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s skipping recalculation, same route", w.handler.String())
		return nil
	}

	// If the chosen route was assigned to a different peer, remove the allowed IPs first
	if isNew := w.currentChosen == nil; !isNew {
		log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s removing old route for HA switch", w.handler.String())
		if err := w.removeAllowedIPs(w.currentChosen, reasonHA); err != nil {
			return fmt.Errorf("remove old: %w", err)
		}
	}

	newChosenRoute := w.routes[newChosenID]
	log.Warnf("[DNS-ROUTE] Watcher.recalculateRoutes: handler=%s adding new route peer=%s network=%s",
		w.handler.String(), newChosenRoute.Peer, newChosenRoute.Network)
	if err := w.addAllowedIPs(newChosenRoute); err != nil {
		return fmt.Errorf("add new: %w", err)
	}
	if newStatus.status != peer.StatusIdle {
		w.connectEvent(newChosenRoute)
	}

	w.currentChosen = newChosenRoute
	w.currentChosenStatus = &newStatus

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
	for {
		select {
		case <-w.ctx.Done():
			return
		case routersStates := <-w.peerStateUpdate:
			routerPeerStatuses := w.convertRouterPeerStatuses(routersStates)
			if err := w.recalculateRoutes(reasonPeerUpdate, routerPeerStatuses); err != nil {
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
	log.Warnf("[DNS-ROUTE] Watcher.handleRouteUpdate: handler=%s serial=%d routes=%d",
		w.handler.String(), update.UpdateSerial, len(update.Routes))
	log.Debugf("Received a new client network route update for [%v]", w.handler)

	// hash update somehow
	isTrueRouteUpdate := w.classifyUpdate(update)

	w.updateSerial = update.UpdateSerial

	if isTrueRouteUpdate {
		log.Warnf("[DNS-ROUTE] Watcher.handleRouteUpdate: handler=%s routes changed, recalculating", w.handler.String())
		log.Debugf("client network update %v for [%v] contains different routes, recalculating routes", update.UpdateSerial, w.handler)
		routePeerStatuses := w.getRouterPeerStatuses()
		log.Warnf("[DNS-ROUTE] Watcher.handleRouteUpdate: handler=%s peerStatuses=%d", w.handler.String(), len(routePeerStatuses))
		if err := w.recalculateRoutes(reasonRouteUpdate, routePeerStatuses); err != nil {
			log.Errorf("failed to recalculate routes for network [%v]: %v", w.handler, err)
		}
	} else {
		log.Warnf("[DNS-ROUTE] Watcher.handleRouteUpdate: handler=%s no changes, skipping", w.handler.String())
		log.Debugf("route update %v for [%v] is not different, skipping route recalculation", update.UpdateSerial, w.handler)
	}

	w.startNewPeerStatusWatchers()
}

// Stop stops the watcher and cleans up resources.
func (w *Watcher) Stop() {
	log.Debugf("Stopping watcher for network [%v]", w.handler)

	w.cancel()

	if w.currentChosen == nil {
		return
	}
	if err := w.removeAllowedIPs(w.currentChosen, reasonShutdown); err != nil {
		log.Errorf("Failed to remove routes for [%v]: %v", w.handler, err)
	}
	w.currentChosenStatus = nil
}

func HandlerFromRoute(params common.HandlerParams) RouteHandler {
	ht := handlerType(params.Route, params.UseNewDNSRoute)
	var handlerName string
	switch ht {
	case handlerTypeDnsInterceptor:
		handlerName = "DnsInterceptor"
	case handlerTypeDynamic:
		handlerName = "Dynamic"
	default:
		handlerName = "Static"
	}
	log.Warnf("[DNS-ROUTE] HandlerFromRoute: route=%s isDynamic=%v useNewDNSRoute=%v -> handler=%s",
		params.Route.Network, params.Route.IsDynamic(), params.UseNewDNSRoute, handlerName)

	switch ht {
	case handlerTypeDnsInterceptor:
		return dnsinterceptor.New(params)
	case handlerTypeDynamic:
		dns := nbdns.NewServiceViaMemory(params.WgInterface)
		dnsAddr := fmt.Sprintf("%s:%d", dns.RuntimeIP(), dns.RuntimePort())
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
