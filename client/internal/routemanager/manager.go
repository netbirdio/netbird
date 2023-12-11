package routemanager

import (
	"context"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/version"
)

// Manager is a route manager interface
type Manager interface {
	UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error
	SetRouteChangeListener(listener listener.NetworkChangeListener)
	InitialRouteRange() []string
	EnableServerRouter(firewall firewall.Manager) error
	Stop()
}

// DefaultManager is the default instance of a route manager
type DefaultManager struct {
	ctx            context.Context
	stop           context.CancelFunc
	mux            sync.Mutex
	clientNetworks map[string]*clientNetwork
	serverRouter   serverRouter
	statusRecorder *peer.Status
	wgInterface    *iface.WGIface
	pubKey         string
	notifier       *notifier
}

func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *peer.Status, initialRoutes []*route.Route) *DefaultManager {
	mCTX, cancel := context.WithCancel(ctx)
	dm := &DefaultManager{
		ctx:            mCTX,
		stop:           cancel,
		clientNetworks: make(map[string]*clientNetwork),
		statusRecorder: statusRecorder,
		wgInterface:    wgInterface,
		pubKey:         pubKey,
		notifier:       newNotifier(),
	}

	if runtime.GOOS == "android" {
		cr := dm.clientRoutes(initialRoutes)
		dm.notifier.setInitialClientRoutes(cr)
	}
	return dm
}

func (m *DefaultManager) EnableServerRouter(firewall firewall.Manager) error {
	var err error
	m.serverRouter, err = newServerRouter(m.ctx, m.wgInterface, firewall)
	if err != nil {
		return err
	}
	return nil
}

// Stop stops the manager watchers and clean firewall rules
func (m *DefaultManager) Stop() {
	m.stop()
	if m.serverRouter != nil {
		m.serverRouter.cleanUp()
	}
	m.ctx = nil
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

		newServerRoutesMap, newClientRoutesIDMap := m.classifiesRoutes(newRoutes)

		m.updateClientNetworks(updateSerial, newClientRoutesIDMap)
		m.notifier.onNewRoutes(newClientRoutesIDMap)

		if m.serverRouter != nil {
			err := m.serverRouter.updateRoutes(newServerRoutesMap)
			if err != nil {
				return err
			}
		}

		return nil
	}
}

// SetRouteChangeListener set RouteListener for route change notifier
func (m *DefaultManager) SetRouteChangeListener(listener listener.NetworkChangeListener) {
	m.notifier.setListener(listener)
}

// InitialRouteRange return the list of initial routes. It used by mobile systems
func (m *DefaultManager) InitialRouteRange() []string {
	return m.notifier.initialRouteRanges()
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

func (m *DefaultManager) classifiesRoutes(newRoutes []*route.Route) (map[string]*route.Route, map[string][]*route.Route) {
	newClientRoutesIDMap := make(map[string][]*route.Route)
	newServerRoutesMap := make(map[string]*route.Route)
	ownNetworkIDs := make(map[string]bool)

	for _, newRoute := range newRoutes {
		networkID := route.GetHAUniqueID(newRoute)
		if newRoute.Peer == m.pubKey {
			ownNetworkIDs[networkID] = true
			// only linux is supported for now
			if runtime.GOOS != "linux" {
				log.Warnf("received a route to manage, but agent doesn't support router mode on %s OS", runtime.GOOS)
				continue
			}
			newServerRoutesMap[newRoute.ID] = newRoute
		}
	}

	for _, newRoute := range newRoutes {
		networkID := route.GetHAUniqueID(newRoute)
		if !ownNetworkIDs[networkID] {
			// if prefix is too small, lets assume is a possible default route which is not yet supported
			// we skip this route management
			if newRoute.Network.Bits() < minRangeBits {
				log.Errorf("this agent version: %s, doesn't support default routes, received %s, skipping this route",
					version.NetbirdVersion(), newRoute.Network)
				continue
			}
			newClientRoutesIDMap[networkID] = append(newClientRoutesIDMap[networkID], newRoute)
		}
	}

	return newServerRoutesMap, newClientRoutesIDMap
}

func (m *DefaultManager) clientRoutes(initialRoutes []*route.Route) []*route.Route {
	_, crMap := m.classifiesRoutes(initialRoutes)
	rs := make([]*route.Route, 0)
	for _, routes := range crMap {
		rs = append(rs, routes...)
	}
	return rs
}
