package routemanager

import (
	"context"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/version"
)

// Manager is a route manager interface
type Manager interface {
	UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) error
	Stop()
}

// DefaultManager is the default instance of a route manager
type DefaultManager struct {
	ctx                 context.Context
	stop                context.CancelFunc
	mux                 sync.Mutex
	clientNetworks      map[string]*clientNetwork
	serverRouter        *serverRouter
	statusRecorder      *peer.Status
	wgInterface         *iface.WGIface
	pubKey              string
	initialClientRoutes []*route.Route
}

// NewManager returns a new route manager
func NewManager(ctx context.Context, pubKey string, wgInterface *iface.WGIface, statusRecorder *peer.Status, initialRoutes []*route.Route) *DefaultManager {
	mCTX, cancel := context.WithCancel(ctx)

	dm := &DefaultManager{
		ctx:            mCTX,
		stop:           cancel,
		clientNetworks: make(map[string]*clientNetwork),
		serverRouter:   newServerRouter(ctx, wgInterface),
		statusRecorder: statusRecorder,
		wgInterface:    wgInterface,
		pubKey:         pubKey,
	}

	if runtime.GOOS == "android" {
		cr := dm.clientRoutes(initialRoutes)
		wgInterface.SetInitialRoutes(cr)
	}
	return dm
}

// Stop stops the manager watchers and clean firewall rules
func (m *DefaultManager) Stop() {
	m.stop()
	m.serverRouter.cleanUp()
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

		err := m.serverRouter.updateRoutes(newServerRoutesMap)
		if err != nil {
			return err
		}

		return nil
	}
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
			log.Debugf("new route !ownNetworkIDs: (networkID %v) %s, %s", networkID)

			// if prefix is too small, lets assume is a possible default route which is not yet supported
			// we skip this route management
			if newRoute.Network.Bits() < 7 {
				log.Errorf("this agent version: %s, doesn't support default routes, received %s, skiping this route",
					version.NetbirdVersion(), newRoute.Network)
				continue
			}
			newClientRoutesIDMap[networkID] = append(newClientRoutesIDMap[networkID], newRoute)
		}
	}

	return newServerRoutesMap, newClientRoutesIDMap
}

func (m *DefaultManager) clientRoutes(initialRoutes []*route.Route) []string {
	_, cr := m.classifiesRoutes(initialRoutes)
	rs := make([]string, 0)
	for _, networkID := range cr {
		for _, r := range networkID {
			rs = append(rs, r.Network.String())
		}
	}
	return rs
}
