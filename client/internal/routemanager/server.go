package routemanager

import (
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"sync"
)

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
