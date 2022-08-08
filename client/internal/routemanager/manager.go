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
	ctx             context.Context
	stop            context.CancelFunc
	mux             sync.Mutex
	routes          map[string]*route.Route
	managedPrefixes map[netip.Prefix]*managedPrefix
	statusRecorder  *status.Status
	wgInterface     *iface.WGIface
	pubKey          string
	isRouter        bool
}

// DefaultCheckInterval default route worker check interval 5s
const DefaultCheckInterval time.Duration = 15000000000

type managedPrefix struct {
	ctx         context.Context
	stop        context.CancelFunc
	routes      map[string]*route.Route
	update      chan struct{}
	chosenRoute string
	mux         sync.Mutex
	prefix      netip.Prefix
}

type routerPeerStatus struct {
	connected bool
	relayed   bool
	direct    bool
}

func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *status.Status) *Manager {
	mCTX, cancel := context.WithCancel(ctx)
	return &Manager{
		ctx:             mCTX,
		stop:            cancel,
		routes:          make(map[string]*route.Route),
		managedPrefixes: make(map[netip.Prefix]*managedPrefix),
		statusRecorder:  statusRecorder,
		wgInterface:     wgInterface,
		pubKey:          pubKey,
	}
}

func (m *Manager) Stop() {
	m.stop()
}

func (m *Manager) UpdateRoutes(newRoutes []*route.Route) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	routesToRemove := make([]string, 0)
	routesToUpdate := make([]string, 0)
	routesToAdd := make([]string, 0)
	newRoutesMap := make(map[string]*route.Route)
	shouldRoute := false
	for _, route := range newRoutes {
		newRoutesMap[route.ID] = route
		if route.Peer == m.pubKey && runtime.GOOS == "linux" {
			shouldRoute = true
		}
		_, found := m.routes[route.ID]
		if !found {
			routesToAdd = append(routesToAdd, route.ID)
		}
	}
	for routeID, _ := range m.routes {
		update, found := newRoutesMap[routeID]
		if !found {
			routesToRemove = append(routesToRemove, routeID)
			continue
		}

		if !update.IsEqual(m.routes[routeID]) {
			routesToUpdate = append(routesToUpdate, routeID)
		}
	}

	m.setupRouterMode(shouldRoute)

	for _, routeID := range routesToRemove {
		oldRoute := m.routes[routeID]
		delete(m.routes, routeID)
		m.removeFromPrefix(oldRoute)
	}
	for _, routeID := range routesToUpdate {
		newRoute := newRoutesMap[routeID]
		oldRoute := m.routes[routeID]
		m.routes[routeID] = newRoute
		if newRoute.Prefix != oldRoute.Prefix {
			m.removeFromPrefix(oldRoute)
		}
		m.updatePrefix(newRoute)
	}
	for _, routeID := range routesToAdd {
		newRoute := newRoutesMap[routeID]
		m.routes[routeID] = newRoute
		m.updatePrefix(newRoute)
	}
	for id, prefix := range m.managedPrefixes {
		prefix.mux.Lock()
		if len(prefix.routes) == 0 {
			prefix.stop()
			delete(m.managedPrefixes, id)
		}
		prefix.mux.Unlock()
	}
	log.Info("routes added %d, removed % and updated %d", len(routesToAdd), len(routesToRemove), len(routesToUpdate))
	return nil
}

func (m *Manager) setupRouterMode(shouldRoute bool) {
	m.isRouter = shouldRoute
	if shouldRoute {
		err := enableIPForwarding()
		if err != nil {
			log.Errorf("unable to set ip forwarding please do it manually")
		}
	}
}

func (m *Manager) removeFromPrefix(oldRoute *route.Route) {
	managed, found := m.managedPrefixes[oldRoute.Prefix]
	if !found {
		log.Debugf("managed prefix %s not found", oldRoute.Prefix.String())
		return
	}
	managed.mux.Lock()
	delete(managed.routes, oldRoute.ID)
	managed.mux.Unlock()
	managed.update <- struct{}{}
}

func (m *Manager) startPrefixWatcher(prefixString string) *managedPrefix {
	prefix, _ := netip.ParsePrefix(prefixString)
	ctx, cancel := context.WithCancel(m.ctx)
	managed := &managedPrefix{
		ctx:    ctx,
		stop:   cancel,
		routes: make(map[string]*route.Route),
		update: make(chan struct{}),
		prefix: prefix,
	}
	m.managedPrefixes[prefix] = managed
	go m.watchPrefix(prefix)
	return managed
}

func (m *Manager) updatePrefix(newRoute *route.Route) {
	managed, found := m.managedPrefixes[newRoute.Prefix]
	if !found {
		newRoute.Prefix.Masked()
		managed = m.startPrefixWatcher(newRoute.Prefix.String())
	}
	managed.mux.Lock()
	managed.routes[newRoute.ID] = newRoute
	managed.mux.Unlock()
	managed.update <- struct{}{}
}

func (m *Manager) watchPrefix(prefix netip.Prefix) {
	managed, prefixFound := m.managedPrefixes[prefix]
	if !prefixFound {
		log.Errorf("attepmt to watch prefix %s failed. prefix not found in manager map", prefix.String())
		return
	}
	ticker := time.NewTicker(DefaultCheckInterval)
	go func() {
		for {
			select {
			case <-managed.ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				managed.update <- struct{}{}
			}
		}
	}()

	for {
		select {
		case <-managed.ctx.Done():
			// close things
			// remove prefix from route table
			log.Debugf("stopping routine for prefix %s", managed.prefix)
			managed.mux.Lock()
			err := removeFromRouteTable(managed.prefix)
			if err != nil {
				log.Error(err)
			}
			managed.mux.Unlock()
			return
		case <-managed.update:
			managed.mux.Lock()
			routerPeerStatuses := m.getRouterPeerStatuses(managed.routes)
			chosen := getBestRoute(managed.routes, routerPeerStatuses)
			if chosen != "" {
				if chosen != managed.chosenRoute {
					previousChosen, found := managed.routes[managed.chosenRoute]
					if found {
						removeErr := m.wgInterface.RemoveAllowedIP(previousChosen.Peer, managed.prefix.String())
						if removeErr != nil {
							managed.mux.Unlock()
							continue
						}
						log.Debugf("allowed IP %s removed for peer %s", managed.prefix, previousChosen.Peer)
					}
					managed.chosenRoute = chosen
					chosenRoute := managed.routes[chosen]
					err := m.wgInterface.AddAllowedIP(chosenRoute.Peer, managed.prefix.String())
					if err != nil {
						managed.mux.Unlock()
						continue
					}
					log.Debugf("allowed IP %s added for peer %s", managed.prefix, chosenRoute.Peer)
					if !found {
						err = addToRouteTable(managed.prefix, m.wgInterface.GetAddress().IP.String())
						if err != nil {
							managed.mux.Unlock()
							panic(err)
						}
						log.Debugf("route %s added for peer %s", chosenRoute.Prefix.String(), m.wgInterface.GetAddress().IP.String())
					}
				}
			} else {
				log.Debugf("no route was chosen for prefix %s", managed.prefix)
			}
			managed.mux.Unlock()
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
