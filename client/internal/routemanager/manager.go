package routemanager

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
)

// Manager is a route manager interface
type Manager interface {
	UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error
	Stop()
}

// DefaultManager is the default instance of a route manager
type DefaultManager struct {
	ctx            context.Context
	stop           context.CancelFunc
	mux            sync.Mutex
	clientNetworks map[string]*clientNetwork
	serverRoutes   map[string]*route.Route
	serverRouter   *serverRouter
	statusRecorder *status.Status
	wgInterface    *iface.WGIface
	pubKey         string
}

// NewManager returns a new route manager
func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *status.Status) *DefaultManager {
	mCTX, cancel := context.WithCancel(ctx)
	return &DefaultManager{
		ctx:            mCTX,
		stop:           cancel,
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
func (m *DefaultManager) Stop() {
	m.stop()
	m.serverRouter.firewall.CleanRoutingRules()
}

func (m *DefaultManager) updateClientNetworks(updateSerial uint64, networks map[string][]*route.Route) {
	// removing routes that do not exist as per the update from the Management service.
	for id, client := range m.clientNetworks {
		_, found := networks[id]
		if !found {
			log.Debugf("stopping client network watcher, %s", id)
			client.stop()
			delete(m.clientNetworks, id)
		}
	}

	for id, routes := range networks {
		clientNetworkWatcher, found := m.clientNetworks[id]
		if !found {
			clientNetworkWatcher = newClientNetworkWatcher(m.ctx, m.wgInterface, m.statusRecorder, routes[0].Network)
			m.clientNetworks[id] = clientNetworkWatcher
			go clientNetworkWatcher.peersStateAndUpdateWatcher()
		}
		update := routesUpdate{
			updateSerial: updateSerial,
			routes:       routes,
		}

		clientNetworkWatcher.sendUpdateToClientNetworkWatcher(update)
	}
}

func (m *DefaultManager) updateServerRoutes(routesMap map[string]*route.Route) error {
	serverRoutesToRemove := make([]string, 0)

	if len(routesMap) > 0 {
		err := m.serverRouter.firewall.RestoreOrCreateContainers()
		if err != nil {
			return fmt.Errorf("couldn't initialize firewall containers, got err: %v", err)
		}
	}

	for routeID := range m.serverRoutes {
		update, found := routesMap[routeID]
		if !found || !update.IsEqual(m.serverRoutes[routeID]) {
			serverRoutesToRemove = append(serverRoutesToRemove, routeID)
			continue
		}
	}

	for _, routeID := range serverRoutesToRemove {
		oldRoute := m.serverRoutes[routeID]
		err := m.removeFromServerNetwork(oldRoute)
		if err != nil {
			log.Errorf("unable to remove route id: %s, network %s, from server, got: %v",
				oldRoute.ID, oldRoute.Network, err)
		}
		delete(m.serverRoutes, routeID)
	}

	for id, newRoute := range routesMap {
		_, found := m.serverRoutes[id]
		if found {
			continue
		}

		err := m.addToServerNetwork(newRoute)
		if err != nil {
			log.Errorf("unable to add route %s from server, got: %v", newRoute.ID, err)
			continue
		}
		m.serverRoutes[id] = newRoute
	}

	if len(m.serverRoutes) > 0 {
		err := enableIPForwarding()
		if err != nil {
			return err
		}
	}

	return nil
}

// UpdateRoutes compares received routes with existing routes and remove, update or add them to the client and server maps
func (m *DefaultManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not updating routes as context is closed")
		return m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()

		newClientRoutesIDMap := make(map[string][]*route.Route)
		newServerRoutesMap := make(map[string]*route.Route)
		ownNetworkIDs := make(map[string]bool)

		for _, newRoute := range newRoutes {
			if newRoute.Peer == m.pubKey {
				ownNetworkIDs[getHANetworkID(newRoute)] = true
			}
		}

		for _, newRoute := range newRoutes {
			networkID := getHANetworkID(newRoute)
			if ownNetworkIDs[networkID] {
				// only linux is supported for now
				if runtime.GOOS != "linux" {
					log.Warnf("received a route to manage, but agent doesn't support router mode on %s OS", runtime.GOOS)
					continue
				}
				newServerRoutesMap[newRoute.ID] = newRoute
			} else {
				// if prefix is too small, lets assume is a possible default route which is not yet supported
				// we skip this route management
				if newRoute.Network.Bits() < 7 {
					log.Errorf("this agent version: %s, doesn't support default routes, received %s, skiping this route",
						system.NetbirdVersion(), newRoute.Network)
					continue
				}
				newClientRoutesIDMap[networkID] = append(newClientRoutesIDMap[networkID], newRoute)
			}
		}

		m.updateClientNetworks(updateSerial, newClientRoutesIDMap)

		err := m.updateServerRoutes(newServerRoutesMap)
		if err != nil {
			return err
		}

		return nil
	}
}
