package routemanager

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"net/netip"
)

type routerPeerStatus struct {
	connected bool
	relayed   bool
	direct    bool
}

type routesUpdate struct {
	updateSerial uint64
	routes       []*route.Route
}

type clientNetwork struct {
	ctx                 context.Context
	stop                context.CancelFunc
	statusRecorder      *status.Status
	wgInterface         *iface.WGIface
	routes              map[string]*route.Route
	routeUpdate         chan routesUpdate
	peerStateUpdate     chan struct{}
	routePeersNotifiers map[string]chan struct{}
	chosenRoute         *route.Route
	network             netip.Prefix
	updateSerial        uint64
}

func newClientNetworkWatcher(ctx context.Context, wgInterface *iface.WGIface, statusRecorder *status.Status, network netip.Prefix) *clientNetwork {
	ctx, cancel := context.WithCancel(ctx)
	client := &clientNetwork{
		ctx:                 ctx,
		stop:                cancel,
		statusRecorder:      statusRecorder,
		wgInterface:         wgInterface,
		routes:              make(map[string]*route.Route),
		routePeersNotifiers: make(map[string]chan struct{}),
		routeUpdate:         make(chan routesUpdate),
		peerStateUpdate:     make(chan struct{}),
		network:             network,
	}
	return client
}

func getClientNetworkID(input *route.Route) string {
	return input.NetID + "-" + input.Network.String()
}

func (c *clientNetwork) getRouterPeerStatuses() map[string]routerPeerStatus {
	routePeerStatuses := make(map[string]routerPeerStatus)
	for _, r := range c.routes {
		peerStatus, err := c.statusRecorder.GetPeer(r.Peer)
		if err != nil {
			log.Debugf("couldn't fetch peer state: %v", err)
			continue
		}
		routePeerStatuses[r.ID] = routerPeerStatus{
			connected: peerStatus.ConnStatus == peer.StatusConnected.String(),
			relayed:   peerStatus.Relayed,
			direct:    peerStatus.Direct,
		}
	}
	return routePeerStatuses
}

func (c *clientNetwork) getBestRouteFromStatuses(routePeerStatuses map[string]routerPeerStatus) string {
	var chosen string
	chosenScore := 0

	currID := ""
	if c.chosenRoute != nil {
		currID = c.chosenRoute.ID
	}

	for _, r := range c.routes {
		tempScore := 0
		peerStatus, found := routePeerStatuses[r.ID]
		if !found || !peerStatus.connected {
			continue
		}
		if r.Metric < route.MaxMetric {
			metricDiff := route.MaxMetric - r.Metric
			tempScore = metricDiff * 10
		}
		if !peerStatus.relayed {
			tempScore++
		}
		if !peerStatus.direct {
			tempScore++
		}
		if tempScore > chosenScore || (tempScore == chosenScore && currID == r.ID) {
			chosen = r.ID
			chosenScore = tempScore
		}
	}

	if chosen == "" {
		var peers []string
		for _, r := range c.routes {
			peers = append(peers, r.Peer)
		}
		log.Warnf("no route was chosen for network %s because no peers from list %s were connected", c.network, peers)
	} else {
		log.Infof("chosen route is %s with peer %s with score %d", chosen, c.routes[chosen].Peer, chosenScore)
	}

	return chosen
}

func (c *clientNetwork) watchPeerStatusChanges(ctx context.Context, peer string, peerStateUpdate chan struct{}, closer chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-closer:
			return
		case <-c.statusRecorder.GetPeerStateChangeNotifier(peer):
			peerStateUpdate <- struct{}{}
			log.Debugf("triggered state update for Peer %s", peer)
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

func (c *clientNetwork) removeRouteFromPeerAndSystem() error {
	if c.chosenRoute != nil {
		err := c.wgInterface.RemoveAllowedIP(c.chosenRoute.Peer, c.network.String())
		if err != nil {
			return fmt.Errorf("couldn't remove allowed IP %s removed for peer %s, err: %v",
				c.network, c.chosenRoute.Peer, err)
		}
		err = removeFromRouteTable(c.network)
		if err != nil {
			return fmt.Errorf("couldn't remove route %s from system, err: %v",
				c.network, err)
		}
	}
	return nil
}

func (c *clientNetwork) recalculateRouteAndUpdatePeerAndSystem() error {

	var err error

	routerPeerStatuses := c.getRouterPeerStatuses()

	chosen := c.getBestRouteFromStatuses(routerPeerStatuses)
	if chosen == "" {
		err = c.removeRouteFromPeerAndSystem()
		if err != nil {
			return err
		}
		return nil
	}

	if c.chosenRoute != nil && c.chosenRoute.ID == chosen {
		if c.chosenRoute.IsEqual(c.routes[chosen]) {
			return nil
		}
	}

	if c.chosenRoute != nil {
		err = c.wgInterface.RemoveAllowedIP(c.chosenRoute.Peer, c.network.String())
		if err != nil {
			return fmt.Errorf("couldn't remove allowed IP %s removed from previously chosed peer %s, err: %v",
				c.network, c.chosenRoute.Peer, err)
		}
	} else {
		err = addToRouteTable(c.network, c.wgInterface.GetAddress().IP.String())
		if err != nil {
			return fmt.Errorf("route %s couldn't be added for peer %s, err: %v",
				c.chosenRoute.Network.String(), c.wgInterface.GetAddress().IP.String(), err)
		}
	}

	c.chosenRoute = c.routes[chosen]
	err = c.wgInterface.AddAllowedIP(c.chosenRoute.Peer, c.network.String())
	if err != nil {
		log.Errorf("couldn't add allowed IP %s added for peer %s, err: %v",
			c.network, c.chosenRoute.Peer, err)
	}

	return nil
}

func (c *clientNetwork) handleUpdate(update routesUpdate) {
	if update.updateSerial < c.updateSerial {
		log.Warnf("received a routes update with smaller serial number, ignoring it")
		return
	}

	updateMap := make(map[string]*route.Route)

	for _, r := range update.routes {
		updateMap[r.ID] = r
	}

	for id, r := range c.routes {
		_, found := updateMap[id]
		if !found {
			close(c.routePeersNotifiers[r.Peer])
		}
	}

	c.routes = updateMap
	c.updateSerial = update.updateSerial
}

// stateAndUpdateWatcher is the main point of reacting on client network routing events.
// All the processing related to the client network should be done here. Thread-safe.
func (c *clientNetwork) stateAndUpdateWatcher() {
	for {
		select {
		case <-c.ctx.Done():
			log.Debugf("stopping routine for prefix %s", c.network)
			err := c.removeRouteFromPeerAndSystem()
			if err != nil {
				log.Error(err)
			}
			return
		case <-c.peerStateUpdate:
			err := c.recalculateRouteAndUpdatePeerAndSystem()
			if err != nil {
				log.Error(err)
			}

			c.startPeersStatusChangeWatcher()
		case routes := <-c.routeUpdate:
			c.handleUpdate(routes)

			err := c.recalculateRouteAndUpdatePeerAndSystem()
			if err != nil {
				log.Error(err)
			}

			c.startPeersStatusChangeWatcher()
		}
	}
}
