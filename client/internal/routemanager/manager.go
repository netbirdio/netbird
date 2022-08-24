package routemanager

import (
	"context"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"runtime"
	"sync"
	"time"
)

type Manager struct {
	ctx            context.Context
	stop           context.CancelFunc
	mux            sync.Mutex
	clientRoutes   map[string]*route.Route
	clientPrefixes map[netip.Prefix]*clientPrefix
	serverRoutes   map[string]*route.Route
	serverRouter   *serverRouter
	statusRecorder *status.Status
	wgInterface    *iface.WGIface
	pubKey         string
}

// DefaultClientCheckInterval default route worker check interval 5s
const DefaultClientCheckInterval time.Duration = 15000000000

type clientPrefix struct {
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

type firewallManager interface {
	RestoreOrCreateContainers() error
	InsertRoutingRules(pair RouterPair) error
	RemoveRoutingRules(pair RouterPair) error
}
type RouterPair struct {
	ID          string
	source      string
	destination string
	masquerade  bool
}

// DefaultServerCheckInterval default route worker check interval 5s
const DefaultServerCheckInterval time.Duration = 15000000000

type routerPeerStatus struct {
	connected bool
	relayed   bool
	direct    bool
}

func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *status.Status) *Manager {
	mCTX, cancel := context.WithCancel(ctx)
	return &Manager{
		ctx:            mCTX,
		stop:           cancel,
		clientRoutes:   make(map[string]*route.Route),
		clientPrefixes: make(map[netip.Prefix]*clientPrefix),
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

func (m *Manager) Stop() {
	m.stop()
}

func (m *Manager) UpdateRoutes(newRoutes []*route.Route) error {
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
	for _, route := range newRoutes {
		if route.Peer == m.pubKey && runtime.GOOS == "linux" {
			newServerRoutesMap[route.ID] = route
			_, found := m.serverRoutes[route.ID]
			if !found {
				serverRoutesToAdd = append(serverRoutesToAdd, route.ID)
			}
		} else {
			newClientRoutesMap[route.ID] = route
			_, found := m.clientRoutes[route.ID]
			if !found {
				clientRoutesToAdd = append(clientRoutesToAdd, route.ID)
			}
		}
	}

	if len(newServerRoutesMap) > 0 {
		err := m.serverRouter.firewall.RestoreOrCreateContainers()
		if err != nil {
			// todo
			log.Fatal(err)
		}
	}

	for routeID, _ := range m.clientRoutes {
		update, found := newClientRoutesMap[routeID]
		if !found {
			clientRoutesToRemove = append(clientRoutesToRemove, routeID)
			continue
		}

		if !update.IsEqual(m.clientRoutes[routeID]) {
			clientRoutesToUpdate = append(clientRoutesToUpdate, routeID)
		}
	}

	for routeID, _ := range m.serverRoutes {
		update, found := newServerRoutesMap[routeID]
		if !found {
			serverRoutesToRemove = append(serverRoutesToRemove, routeID)
			continue
		}

		if !update.IsEqual(m.serverRoutes[routeID]) {
			serverRoutesToUpdate = append(serverRoutesToUpdate, routeID)
		}
	}

	log.Infof("client routes to add %d, remove %d and update %d", len(clientRoutesToAdd), len(clientRoutesToRemove), len(clientRoutesToUpdate))

	for _, routeID := range clientRoutesToRemove {
		oldRoute := m.clientRoutes[routeID]
		delete(m.clientRoutes, routeID)
		m.removeFromClientPrefix(oldRoute)
	}
	for _, routeID := range clientRoutesToUpdate {
		newRoute := newClientRoutesMap[routeID]
		oldRoute := m.clientRoutes[routeID]
		m.clientRoutes[routeID] = newRoute
		if newRoute.Network != oldRoute.Network {
			m.removeFromClientPrefix(oldRoute)
		}
		m.updateClientPrefix(newRoute)
	}
	for _, routeID := range clientRoutesToAdd {
		newRoute := newClientRoutesMap[routeID]
		m.clientRoutes[routeID] = newRoute
		m.updateClientPrefix(newRoute)
	}
	for id, prefix := range m.clientPrefixes {
		prefix.mux.Lock()
		if len(prefix.routes) == 0 {
			log.Debugf("stopping client prefix, %s", prefix.prefix)
			prefix.stop()
			delete(m.clientPrefixes, id)
		}
		prefix.mux.Unlock()
	}

	log.Infof("client routes added %d, removed %d and updated %d", len(clientRoutesToAdd), len(clientRoutesToRemove), len(clientRoutesToUpdate))

	for _, routeID := range serverRoutesToRemove {
		oldRoute := m.serverRoutes[routeID]
		err := m.removeFromServerPrefix(oldRoute)
		if err != nil {
			log.Errorf("unable to remove route from server, got: %v", err)
		}
		delete(m.serverRoutes, routeID)
	}
	for _, routeID := range serverRoutesToUpdate {
		newRoute := newServerRoutesMap[routeID]
		oldRoute := m.serverRoutes[routeID]

		var err error
		if newRoute.Network != oldRoute.Network {
			err = m.removeFromServerPrefix(oldRoute)
			if err != nil {
				log.Errorf("unable to update and remove route %s from server, got: %v", oldRoute.ID, err)
				continue
			}
		}
		err = m.addToServerPrefix(newRoute)
		if err != nil {
			log.Errorf("unable to update and add route %s from server, got: %v", newRoute.ID, err)
			continue
		}
		m.serverRoutes[routeID] = newRoute
	}
	for _, routeID := range serverRoutesToAdd {
		newRoute := newServerRoutesMap[routeID]
		err := m.addToServerPrefix(newRoute)
		if err != nil {
			log.Errorf("unable to add route %s from server, got: %v", newRoute.ID, err)
			continue
		}
		m.serverRoutes[routeID] = newRoute
	}

	if len(m.serverRoutes) > 0 {
		enableIPForwarding()
	}

	log.Infof("server routes added %d, removed %d and updated %d", len(serverRoutesToAdd), len(serverRoutesToRemove), len(serverRoutesToUpdate))
	return nil
}

func (m *Manager) removeFromClientPrefix(oldRoute *route.Route) {
	client, found := m.clientPrefixes[oldRoute.Network]
	if !found {
		log.Debugf("managed prefix %s not found", oldRoute.Network.String())
		return
	}
	client.mux.Lock()
	delete(client.routes, oldRoute.ID)
	client.mux.Unlock()
	client.update <- struct{}{}
}

func (m *Manager) startClientPrefixWatcher(prefixString string) *clientPrefix {
	prefix, _ := netip.ParsePrefix(prefixString)
	ctx, cancel := context.WithCancel(m.ctx)
	client := &clientPrefix{
		ctx:    ctx,
		stop:   cancel,
		routes: make(map[string]*route.Route),
		update: make(chan struct{}),
		prefix: prefix,
	}
	m.clientPrefixes[prefix] = client
	go m.watchClientPrefixes(prefix)
	return client
}

func (m *Manager) updateClientPrefix(newRoute *route.Route) {
	client, found := m.clientPrefixes[newRoute.Network]
	if !found {
		client = m.startClientPrefixWatcher(newRoute.Network.String())
	}
	client.mux.Lock()
	client.routes[newRoute.ID] = newRoute
	client.mux.Unlock()
	client.update <- struct{}{}
}

func (m *Manager) watchClientPrefixes(prefix netip.Prefix) {
	client, prefixFound := m.clientPrefixes[prefix]
	if !prefixFound {
		log.Errorf("attepmt to watch prefix %s failed. prefix not found in manager map", prefix.String())
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
			// close things
			// remove prefix from route table
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
							client.mux.Unlock()
							continue
						}
						log.Debugf("allowed IP %s removed for peer %s", client.prefix, previousChosen.Peer)
					}
					client.chosenRoute = chosen
					chosenRoute := client.routes[chosen]
					err := m.wgInterface.AddAllowedIP(chosenRoute.Peer, client.prefix.String())
					if err != nil {
						client.mux.Unlock()
						continue
					}
					log.Debugf("allowed IP %s added for peer %s", client.prefix, chosenRoute.Peer)
					if !found {
						err = addToRouteTable(client.prefix, m.wgInterface.GetAddress().IP.String())
						if err != nil {
							client.mux.Unlock()
							panic(err)
						}
						log.Debugf("route %s added for peer %s", chosenRoute.Network.String(), m.wgInterface.GetAddress().IP.String())
					}
				} else {
					log.Debugf("no change on chossen route for prefix %s", client.prefix)
				}
			} else {
				log.Debugf("no route was chosen for prefix %s", client.prefix)
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
		status, found := routePeerStatuses[r.ID]
		if !found || !status.connected {
			continue
		}
		if r.Metric < route.MaxMetric {
			metricDiff := route.MaxMetric - r.Metric
			tempScore = metricDiff * 10
		}
		if !status.relayed {
			tempScore++
		}
		if !status.direct {
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
	for _, route := range routes {
		peerStatus, err := m.statusRecorder.GetPeer(route.Peer)
		if err != nil {
			log.Debugf("couldn't fetch peer state: %v", err)
			continue
		}
		routePeerStatuses[route.ID] = routerPeerStatus{
			connected: peerStatus.ConnStatus == peer.StatusConnected.String(),
			relayed:   peerStatus.Relayed,
			direct:    peerStatus.Direct,
		}
	}
	return routePeerStatuses
}

func routeToRouterPair(source string, route *route.Route) RouterPair {
	parsed := netip.MustParsePrefix(source).Masked()
	return RouterPair{
		ID:          route.ID,
		source:      parsed.String(),
		destination: route.Network.Masked().String(),
		masquerade:  route.Masquerade,
	}
}

func (m *Manager) removeFromServerPrefix(route *route.Route) error {
	m.serverRouter.mux.Lock()
	defer m.serverRouter.mux.Unlock()
	err := m.serverRouter.firewall.RemoveRoutingRules(routeToRouterPair(m.wgInterface.Address.String(), route))
	if err != nil {
		return err
	}
	delete(m.serverRouter.routes, route.ID)
	return nil
}

func (m *Manager) addToServerPrefix(route *route.Route) error {
	m.serverRouter.mux.Lock()
	defer m.serverRouter.mux.Unlock()
	err := m.serverRouter.firewall.InsertRoutingRules(routeToRouterPair(m.wgInterface.Address.String(), route))
	if err != nil {
		return err
	}
	m.serverRouter.routes[route.ID] = route
	return nil
}
