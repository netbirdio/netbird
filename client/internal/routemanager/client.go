package routemanager

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/dynamic"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/static"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

type routerPeerStatus struct {
	connected bool
	relayed   bool
	direct    bool
	latency   time.Duration
}

type routesUpdate struct {
	updateSerial uint64
	routes       []*route.Route
}

// RouteHandler defines the interface for handling routes
type RouteHandler interface {
	String() string
	AddRoute(ctx context.Context) error
	RemoveRoute() error
	AddAllowedIPs(peerKey string) error
	RemoveAllowedIPs() error
}

type clientNetwork struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	statusRecorder      *peer.Status
	wgInterface         *iface.WGIface
	routes              map[route.ID]*route.Route
	routeUpdate         chan routesUpdate
	peerStateUpdate     chan struct{}
	routePeersNotifiers map[string]chan struct{}
	currentChosen       *route.Route
	handler             RouteHandler
	updateSerial        uint64
}

func newClientNetworkWatcher(ctx context.Context, dnsRouteInterval time.Duration, wgInterface *iface.WGIface, statusRecorder *peer.Status, rt *route.Route, routeRefCounter *refcounter.RouteRefCounter, allowedIPsRefCounter *refcounter.AllowedIPsRefCounter) *clientNetwork {
	ctx, cancel := context.WithCancel(ctx)

	client := &clientNetwork{
		ctx:                 ctx,
		cancel:              cancel,
		statusRecorder:      statusRecorder,
		wgInterface:         wgInterface,
		routes:              make(map[route.ID]*route.Route),
		routePeersNotifiers: make(map[string]chan struct{}),
		routeUpdate:         make(chan routesUpdate),
		peerStateUpdate:     make(chan struct{}),
		handler:             handlerFromRoute(rt, routeRefCounter, allowedIPsRefCounter, dnsRouteInterval, statusRecorder),
	}
	return client
}

func (c *clientNetwork) getRouterPeerStatuses() map[route.ID]routerPeerStatus {
	routePeerStatuses := make(map[route.ID]routerPeerStatus)
	for _, r := range c.routes {
		peerStatus, err := c.statusRecorder.GetPeer(r.Peer)
		if err != nil {
			log.Debugf("couldn't fetch peer state: %v", err)
			continue
		}
		routePeerStatuses[r.ID] = routerPeerStatus{
			connected: peerStatus.ConnStatus == peer.StatusConnected,
			relayed:   peerStatus.Relayed,
			direct:    peerStatus.Direct,
			latency:   peerStatus.Latency,
		}
	}
	return routePeerStatuses
}

// getBestRouteFromStatuses determines the most optimal route from the available routes
// within a clientNetwork, taking into account peer connection status, route metrics, and
// preference for non-relayed and direct connections.
//
// It follows these prioritization rules:
// * Connected peers: Only routes with connected peers are considered.
// * Metric: Routes with lower metrics (better) are prioritized.
// * Non-relayed: Routes without relays are preferred.
// * Direct connections: Routes with direct peer connections are favored.
// * Latency: Routes with lower latency are prioritized.
// * Stability: In case of equal scores, the currently active route (if any) is maintained.
//
// It returns the ID of the selected optimal route.
func (c *clientNetwork) getBestRouteFromStatuses(routePeerStatuses map[route.ID]routerPeerStatus) route.ID {
	chosen := route.ID("")
	chosenScore := float64(0)
	currScore := float64(0)

	currID := route.ID("")
	if c.currentChosen != nil {
		currID = c.currentChosen.ID
	}

	for _, r := range c.routes {
		tempScore := float64(0)
		peerStatus, found := routePeerStatuses[r.ID]
		if !found || !peerStatus.connected {
			continue
		}

		if r.Metric < route.MaxMetric {
			metricDiff := route.MaxMetric - r.Metric
			tempScore = float64(metricDiff) * 10
		}

		// in some temporal cases, latency can be 0, so we set it to 1s to not block but try to avoid this route
		latency := time.Second
		if peerStatus.latency != 0 {
			latency = peerStatus.latency
		} else {
			log.Warnf("peer %s has 0 latency", r.Peer)
		}
		tempScore += 1 - latency.Seconds()

		if !peerStatus.relayed {
			tempScore++
		}

		if peerStatus.direct {
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

	switch {
	case chosen == "":
		var peers []string
		for _, r := range c.routes {
			peers = append(peers, r.Peer)
		}

		log.Warnf("The network [%v] has not been assigned a routing peer as no peers from the list %s are currently connected", c.handler, peers)
	case chosen != currID:
		// we compare the current score + 10ms to the chosen score to avoid flapping between routes
		if currScore != 0 && currScore+0.01 > chosenScore {
			log.Debugf("Keeping current routing peer because the score difference with latency is less than 0.01(10ms), current: %f, new: %f", currScore, chosenScore)
			return currID
		}
		var p string
		if rt := c.routes[chosen]; rt != nil {
			p = rt.Peer
		}
		log.Infof("New chosen route is %s with peer %s with score %f for network [%v]", chosen, p, chosenScore, c.handler)
	}

	return chosen
}

func (c *clientNetwork) watchPeerStatusChanges(ctx context.Context, peerKey string, peerStateUpdate chan struct{}, closer chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-closer:
			return
		case <-c.statusRecorder.GetPeerStateChangeNotifier(peerKey):
			state, err := c.statusRecorder.GetPeer(peerKey)
			if err != nil || state.ConnStatus == peer.StatusConnecting {
				continue
			}
			peerStateUpdate <- struct{}{}
			log.Debugf("triggered route state update for Peer %s, state: %s", peerKey, state.ConnStatus)
		}
	}
}

func (c *clientNetwork) startPeersStatusChangeWatcher() {
	for _, r := range c.routes {
		_, found := c.routePeersNotifiers[r.Peer]
		if !found {
			c.routePeersNotifiers[r.Peer] = make(chan struct{})
			go c.watchPeerStatusChanges(c.ctx, r.Peer, c.peerStateUpdate, c.routePeersNotifiers[r.Peer])
		}
	}
}

func (c *clientNetwork) removeRouteFromWireguardPeer(peerKey string) error {
	c.removeStateRoute()

	state, err := c.statusRecorder.GetPeer(peerKey)
	if err != nil {
		return fmt.Errorf("get peer state: %w", err)
	}

	if state.ConnStatus != peer.StatusConnected {
		return nil
	}

	if err = c.handler.RemoveAllowedIPs(); err != nil {
		return fmt.Errorf("remove allowed IPs: %w", err)
	}
	return nil
}

func (c *clientNetwork) removeRouteFromPeerAndSystem() error {
	if c.currentChosen == nil {
		return nil
	}

	var merr *multierror.Error

	if err := c.removeRouteFromWireguardPeer(c.currentChosen.Peer); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove allowed IPs for peer %s: %w", c.currentChosen.Peer, err))
	}
	if err := c.handler.RemoveRoute(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove route: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (c *clientNetwork) recalculateRouteAndUpdatePeerAndSystem() error {
	routerPeerStatuses := c.getRouterPeerStatuses()

	newChosenID := c.getBestRouteFromStatuses(routerPeerStatuses)

	// If no route is chosen, remove the route from the peer and system
	if newChosenID == "" {
		if err := c.removeRouteFromPeerAndSystem(); err != nil {
			return fmt.Errorf("remove route for peer %s: %w", c.currentChosen.Peer, err)
		}

		c.currentChosen = nil

		return nil
	}

	// If the chosen route is the same as the current route, do nothing
	if c.currentChosen != nil && c.currentChosen.ID == newChosenID &&
		c.currentChosen.IsEqual(c.routes[newChosenID]) {
		return nil
	}

	if c.currentChosen == nil {
		// If they were not previously assigned to another peer, add routes to the system first
		if err := c.handler.AddRoute(c.ctx); err != nil {
			return fmt.Errorf("add route: %w", err)
		}
	} else {
		// Otherwise, remove the allowed IPs from the previous peer first
		if err := c.removeRouteFromWireguardPeer(c.currentChosen.Peer); err != nil {
			return fmt.Errorf("remove allowed IPs for peer %s: %w", c.currentChosen.Peer, err)
		}
	}

	c.currentChosen = c.routes[newChosenID]

	if err := c.handler.AddAllowedIPs(c.currentChosen.Peer); err != nil {
		return fmt.Errorf("add allowed IPs for peer %s: %w", c.currentChosen.Peer, err)
	}

	c.addStateRoute()

	return nil
}

func (c *clientNetwork) addStateRoute() {
	state, err := c.statusRecorder.GetPeer(c.currentChosen.Peer)
	if err != nil {
		log.Errorf("Failed to get peer state: %v", err)
		return
	}

	state.AddRoute(c.handler.String())
	if err := c.statusRecorder.UpdatePeerState(state); err != nil {
		log.Warnf("Failed to update peer state: %v", err)
	}
}

func (c *clientNetwork) removeStateRoute() {
	state, err := c.statusRecorder.GetPeer(c.currentChosen.Peer)
	if err != nil {
		log.Errorf("Failed to get peer state: %v", err)
		return
	}

	state.DeleteRoute(c.handler.String())
	if err := c.statusRecorder.UpdatePeerState(state); err != nil {
		log.Warnf("Failed to update peer state: %v", err)
	}
}

func (c *clientNetwork) sendUpdateToClientNetworkWatcher(update routesUpdate) {
	go func() {
		c.routeUpdate <- update
	}()
}

func (c *clientNetwork) handleUpdate(update routesUpdate) {
	updateMap := make(map[route.ID]*route.Route)

	for _, r := range update.routes {
		updateMap[r.ID] = r
	}

	for id, r := range c.routes {
		_, found := updateMap[id]
		if !found {
			close(c.routePeersNotifiers[r.Peer])
			delete(c.routePeersNotifiers, r.Peer)
		}
	}

	c.routes = updateMap
}

// peersStateAndUpdateWatcher is the main point of reacting on client network routing events.
// All the processing related to the client network should be done here. Thread-safe.
func (c *clientNetwork) peersStateAndUpdateWatcher() {
	for {
		select {
		case <-c.ctx.Done():
			log.Debugf("Stopping watcher for network [%v]", c.handler)
			if err := c.removeRouteFromPeerAndSystem(); err != nil {
				log.Errorf("Failed to remove routes for [%v]: %v", c.handler, err)
			}
			return
		case <-c.peerStateUpdate:
			err := c.recalculateRouteAndUpdatePeerAndSystem()
			if err != nil {
				log.Errorf("Failed to recalculate routes for network [%v]: %v", c.handler, err)
			}
		case update := <-c.routeUpdate:
			if update.updateSerial < c.updateSerial {
				log.Warnf("Received a routes update with smaller serial number (%d -> %d), ignoring it", c.updateSerial, update.updateSerial)
				continue
			}

			log.Debugf("Received a new client network route update for [%v]", c.handler)

			c.handleUpdate(update)

			c.updateSerial = update.updateSerial

			err := c.recalculateRouteAndUpdatePeerAndSystem()
			if err != nil {
				log.Errorf("Failed to recalculate routes for network [%v]: %v", c.handler, err)
			}

			c.startPeersStatusChangeWatcher()
		}
	}
}

func handlerFromRoute(rt *route.Route, routeRefCounter *refcounter.RouteRefCounter, allowedIPsRefCounter *refcounter.AllowedIPsRefCounter, dnsRouterInteval time.Duration, statusRecorder *peer.Status) RouteHandler {
	if rt.IsDynamic() {
		return dynamic.NewRoute(rt, routeRefCounter, allowedIPsRefCounter, dnsRouterInteval, statusRecorder)
	}
	return static.NewRoute(rt, routeRefCounter, allowedIPsRefCounter)
}
