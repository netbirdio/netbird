package routemanager

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"runtime"
	"sync"
	"time"
)

// Manager is an instance of a route manager
type Manager struct {
	ctx            context.Context
	stop           context.CancelFunc
	mux            sync.Mutex
	clientRoutes   map[string]*route.Route
	clientNetworks map[string]*clientNetwork
	serverRoutes   map[string]*route.Route
	serverRouter   *serverRouter
	statusRecorder *status.Status
	wgInterface    *iface.WGIface
	pubKey         string
}

// DefaultClientCheckInterval default route worker check interval 5s
const DefaultClientCheckInterval time.Duration = 15000000000

type clientNetwork struct {
	ctx         context.Context
	stop        context.CancelFunc
	routes      map[string]*route.Route
	update      chan struct{}
	chosenRoute string
	mux         sync.Mutex
	prefix      netip.Prefix
}

type serverRouter struct {
	routes map[string]*route.Route
	// best effort to keep net forward configuration as it was
	netForwardHistoryEnabled bool
	mux                      sync.Mutex
	firewall                 firewallManager
}

type routerPair struct {
	ID          string
	source      string
	destination string
	masquerade  bool
}

type routerPeerStatus struct {
	connected bool
	relayed   bool
	direct    bool
}

// NewManager returns a new route manager
func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *status.Status) *Manager {
	mCTX, cancel := context.WithCancel(ctx)
	return &Manager{
		ctx:            mCTX,
		stop:           cancel,
		clientRoutes:   make(map[string]*route.Route),
		clientNetworks: make(map[string]*clientNetwork),
		serverRoutes:   make(map[string]*route.Route),
		serverRouter: &serverRouter{
			routes:                   make(map[string]*route.Route),
			netForwardHistoryEnabled: isNetForwardHistoryEnabled(),
			firewall:                 NewFirewall(ctx),
		},
		statusRecorder: statusRecorder,
		wgInterface:    wgInterface,
		pubKey:         pubKey,
	}
}

// Stop stops the manager watchers and clean firewall rules
func (m *Manager) Stop() {
	m.stop()
	m.serverRouter.firewall.CleanRoutingRules()
}

// UpdateRoutes compares received routes with existing routes and remove, update or add them to the client and server maps
func (m *Manager) UpdateRoutes(newRoutes []*route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not updating routes as context is closed")
		return m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()

		clientRoutesToRemove := make([]string, 0)
		clientRoutesToUpdate := make([]string, 0)
		clientRoutesToAdd := make([]string, 0)
		serverRoutesToRemove := make([]string, 0)
		serverRoutesToUpdate := make([]string, 0)
		serverRoutesToAdd := make([]string, 0)
		newClientRoutesMap := make(map[string]*route.Route)
		newServerRoutesMap := make(map[string]*route.Route)

		for _, newRoute := range newRoutes {
			// only linux is supported for now
			if newRoute.Peer == m.pubKey {
				if runtime.GOOS != "linux" {
					log.Warnf("received a route to manage, but agent doesn't support router mode on %s OS", runtime.GOOS)
					continue
				}
				newServerRoutesMap[newRoute.ID] = newRoute
				_, found := m.serverRoutes[newRoute.ID]
				if !found {
					serverRoutesToAdd = append(serverRoutesToAdd, newRoute.ID)
				}
			} else {
				// if prefix is too small, lets assume is a possible default route which is not yet supported
				// we skip this route management
				if newRoute.Network.Bits() < 7 {
					log.Errorf("this agent version: %s, doesn't support default routes, received %s, skiping this route",
						system.NetbirdVersion(), newRoute.Network)
					continue
				}

				newClientRoutesMap[newRoute.ID] = newRoute
				_, found := m.clientRoutes[newRoute.ID]
				if !found {
					clientRoutesToAdd = append(clientRoutesToAdd, newRoute.ID)
				}
			}
		}

		if len(newServerRoutesMap) > 0 {
			err := m.serverRouter.firewall.RestoreOrCreateContainers()
			if err != nil {
				return fmt.Errorf("couldn't initialize firewall containers, got err: %v", err)
			}
		}

		for routeID := range m.clientRoutes {
			update, found := newClientRoutesMap[routeID]
			if !found {
				clientRoutesToRemove = append(clientRoutesToRemove, routeID)
				continue
			}

			if !update.IsEqual(m.clientRoutes[routeID]) {
				clientRoutesToUpdate = append(clientRoutesToUpdate, routeID)
			}
		}

		for routeID := range m.serverRoutes {
			update, found := newServerRoutesMap[routeID]
			if !found {
				serverRoutesToRemove = append(serverRoutesToRemove, routeID)
				continue
			}

			if !update.IsEqual(m.serverRoutes[routeID]) {
				serverRoutesToUpdate = append(serverRoutesToUpdate, routeID)
			}
		}

		log.Infof("client routes to add %d, remove %d and update %d",
			len(clientRoutesToAdd), len(clientRoutesToRemove), len(clientRoutesToUpdate))

		for _, routeID := range clientRoutesToRemove {
			oldRoute := m.clientRoutes[routeID]
			delete(m.clientRoutes, routeID)
			m.removeFromClientNetwork(oldRoute)
		}
		for _, routeID := range clientRoutesToUpdate {
			newRoute := newClientRoutesMap[routeID]
			oldRoute := m.clientRoutes[routeID]
			m.clientRoutes[routeID] = newRoute
			if newRoute.Network != oldRoute.Network {
				m.removeFromClientNetwork(oldRoute)
			}
			m.updateClientNetwork(newRoute)
		}
		for _, routeID := range clientRoutesToAdd {
			newRoute := newClientRoutesMap[routeID]
			m.clientRoutes[routeID] = newRoute
			m.updateClientNetwork(newRoute)
		}
		for id, prefix := range m.clientNetworks {
			prefix.mux.Lock()
			if len(prefix.routes) == 0 {
				log.Debugf("stopping client prefix, %s", prefix.prefix)
				prefix.stop()
				delete(m.clientNetworks, id)
			}
			prefix.mux.Unlock()
		}

		log.Infof("client routes added %d, removed %d and updated %d",
			len(clientRoutesToAdd), len(clientRoutesToRemove), len(clientRoutesToUpdate))

		for _, routeID := range serverRoutesToRemove {
			oldRoute := m.serverRoutes[routeID]
			err := m.removeFromServerNetwork(oldRoute)
			if err != nil {
				log.Errorf("unable to remove route id: %s, network %s, from server, got: %v",
					oldRoute.ID, oldRoute.Network, err)
			}
			delete(m.serverRoutes, routeID)
		}
		for _, routeID := range serverRoutesToUpdate {
			newRoute := newServerRoutesMap[routeID]
			oldRoute := m.serverRoutes[routeID]

			var err error
			if newRoute.Network != oldRoute.Network {
				err = m.removeFromServerNetwork(oldRoute)
				if err != nil {
					log.Errorf("unable to remove route id: %s, network %s, from server, got: %v",
						oldRoute.ID, oldRoute.Network, err)
					continue
				}
			}

			err = m.addToServerNetwork(newRoute)
			if err != nil {
				log.Errorf("unable to update and add route id: %s, network: %s, to server, got: %v",
					newRoute.ID, newRoute.Network, err)
				continue
			}
			m.serverRoutes[routeID] = newRoute
		}
		for _, routeID := range serverRoutesToAdd {
			newRoute := newServerRoutesMap[routeID]
			err := m.addToServerNetwork(newRoute)
			if err != nil {
				log.Errorf("unable to add route %s from server, got: %v", newRoute.ID, err)
				continue
			}
			m.serverRoutes[routeID] = newRoute
		}

		log.Infof("server routes added %d, removed %d and updated %d",
			len(serverRoutesToAdd), len(serverRoutesToRemove), len(serverRoutesToUpdate))

		if len(m.serverRoutes) > 0 {
			err := enableIPForwarding()
			if err != nil {
				return err
			}
		}

		return nil
	}
}

func getClientNetworkID(input *route.Route) string {
	return input.NetID + "-" + input.Network.String()
}

func (m *Manager) removeFromClientNetwork(oldRoute *route.Route) {
	select {
	case <-m.ctx.Done():
		log.Infof("not removing from client network because context is done: %v", m.ctx.Err())
		return
	default:
		client, found := m.clientNetworks[getClientNetworkID(oldRoute)]
		if !found {
			log.Debugf("managed prefix %s not found", oldRoute.Network.String())
			return
		}
		client.mux.Lock()
		delete(client.routes, oldRoute.ID)
		client.mux.Unlock()
		client.update <- struct{}{}
	}
}

func (m *Manager) startClientNetworkWatcher(networkRoute *route.Route) *clientNetwork {
	ctx, cancel := context.WithCancel(m.ctx)
	client := &clientNetwork{
		ctx:    ctx,
		stop:   cancel,
		routes: make(map[string]*route.Route),
		update: make(chan struct{}),
		prefix: networkRoute.Network,
	}
	id := getClientNetworkID(networkRoute)
	m.clientNetworks[id] = client
	go m.watchClientNetworks(id)
	return client
}

func (m *Manager) updateClientNetwork(newRoute *route.Route) {
	select {
	case <-m.ctx.Done():
		log.Infof("not updating client network because context is done: %v", m.ctx.Err())
		return
	default:
		client, found := m.clientNetworks[newRoute.NetID+newRoute.Network.String()]
		if !found {
			client = m.startClientNetworkWatcher(newRoute)
		}
		client.mux.Lock()
		client.routes[newRoute.ID] = newRoute
		client.mux.Unlock()
		client.update <- struct{}{}
	}
}

func (m *Manager) watchClientNetworks(id string) {
	client, prefixFound := m.clientNetworks[id]
	if !prefixFound {
		log.Errorf("attepmt to watch prefix %s failed. prefix not found in manager map", id)
		return
	}
	ticker := time.NewTicker(DefaultClientCheckInterval)
	go func() {
		for {
			select {
			case <-client.ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				client.update <- struct{}{}
			}
		}
	}()

	for {
		select {
		case <-client.ctx.Done():
			log.Debugf("stopping routine for prefix %s", client.prefix)
			client.mux.Lock()
			err := removeFromRouteTable(client.prefix)
			if err != nil {
				log.Error(err)
			}
			client.mux.Unlock()
			return
		case <-client.update:
			client.mux.Lock()
			routerPeerStatuses := m.getRouterPeerStatuses(client.routes)
			chosen := getBestRoute(client.routes, routerPeerStatuses)
			if chosen != "" {
				if chosen != client.chosenRoute {
					previousChosen, found := client.routes[client.chosenRoute]
					if found {
						removeErr := m.wgInterface.RemoveAllowedIP(previousChosen.Peer, client.prefix.String())
						if removeErr != nil {
							log.Debugf("couldn't remove allowed IP %s removed for peer %s, err: %v",
								client.prefix, previousChosen.Peer, removeErr)
							client.mux.Unlock()
							continue
						}
						log.Debugf("allowed IP %s removed for peer %s", client.prefix, previousChosen.Peer)
					}
					client.chosenRoute = chosen
					chosenRoute := client.routes[chosen]
					err := m.wgInterface.AddAllowedIP(chosenRoute.Peer, client.prefix.String())
					if err != nil {
						log.Errorf("couldn't add allowed IP %s added for peer %s, err: %v",
							client.prefix, chosenRoute.Peer, err)
						client.mux.Unlock()
						continue
					}
					log.Debugf("allowed IP %s added for peer %s", client.prefix, chosenRoute.Peer)
					if !found {
						err = addToRouteTable(client.prefix, m.wgInterface.GetAddress().IP.String())
						if err != nil {
							log.Errorf("route %s couldn't be added for peer %s, err: %v",
								chosenRoute.Network.String(), m.wgInterface.GetAddress().IP.String(), err)
							client.mux.Unlock()
							continue
						}
						log.Debugf("route %s added for peer %s", chosenRoute.Network.String(), m.wgInterface.GetAddress().IP.String())
					}
				} else {
					log.Debugf("no change on chossen route for prefix %s", client.prefix)
				}
			} else {
				var peers []string
				for _, r := range client.routes {
					peers = append(peers, r.Peer)
				}
				log.Warnf("no route was chosen for prefix %s, no peers from list %s were connected", client.prefix, peers)
			}
			client.mux.Unlock()
		}
	}
}

func getBestRoute(routes map[string]*route.Route, routePeerStatuses map[string]routerPeerStatus) string {
	var chosen string
	chosenScore := 0

	for _, r := range routes {
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
		if tempScore > chosenScore {
			chosen = r.ID
			chosenScore = tempScore
		}
	}
	log.Debugf("chosen route is %s with score of %d", chosen, chosenScore)
	return chosen
}

func (m *Manager) getRouterPeerStatuses(routes map[string]*route.Route) map[string]routerPeerStatus {
	routePeerStatuses := make(map[string]routerPeerStatus)
	for _, r := range routes {
		peerStatus, err := m.statusRecorder.GetPeer(r.Peer)
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

func routeToRouterPair(source string, route *route.Route) routerPair {
	parsed := netip.MustParsePrefix(source).Masked()
	return routerPair{
		ID:          route.ID,
		source:      parsed.String(),
		destination: route.Network.Masked().String(),
		masquerade:  route.Masquerade,
	}
}

func (m *Manager) removeFromServerNetwork(route *route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not removing from server network because context is done")
		return m.ctx.Err()
	default:
		m.serverRouter.mux.Lock()
		defer m.serverRouter.mux.Unlock()
		err := m.serverRouter.firewall.RemoveRoutingRules(routeToRouterPair(m.wgInterface.Address.String(), route))
		if err != nil {
			return err
		}
		delete(m.serverRouter.routes, route.ID)
		return nil
	}
}

func (m *Manager) addToServerNetwork(route *route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not adding to server network because context is done")
		return m.ctx.Err()
	default:
		m.serverRouter.mux.Lock()
		defer m.serverRouter.mux.Unlock()
		err := m.serverRouter.firewall.InsertRoutingRules(routeToRouterPair(m.wgInterface.Address.String(), route))
		if err != nil {
			return err
		}
		m.serverRouter.routes[route.ID] = route
		return nil
	}
}
