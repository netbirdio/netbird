//go:build !android

package routemanager

import (
	"context"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

type defaultServerRouter struct {
	mux         sync.Mutex
	ctx         context.Context
	routes      map[string]*route.Route
	firewall    firewall.Manager
	wgInterface *iface.WGIface
}

func newServerRouter(ctx context.Context, wgInterface *iface.WGIface, firewall firewall.Manager) (serverRouter, error) {
	return &defaultServerRouter{
		ctx:         ctx,
		routes:      make(map[string]*route.Route),
		firewall:    firewall,
		wgInterface: wgInterface,
	}, nil
}

func (m *defaultServerRouter) updateRoutes(routesMap map[string]*route.Route) error {
	serverRoutesToRemove := make([]string, 0)

	for routeID := range m.routes {
		update, found := routesMap[routeID]
		if !found || !update.IsEqual(m.routes[routeID]) {
			serverRoutesToRemove = append(serverRoutesToRemove, routeID)
		}
	}

	for _, routeID := range serverRoutesToRemove {
		oldRoute := m.routes[routeID]
		err := m.removeFromServerNetwork(oldRoute)
		if err != nil {
			log.Errorf("unable to remove route id: %s, network %s, from server, got: %v",
				oldRoute.ID, oldRoute.Network, err)
		}
		delete(m.routes, routeID)
	}

	for id, newRoute := range routesMap {
		_, found := m.routes[id]
		if found {
			continue
		}

		err := m.addToServerNetwork(newRoute)
		if err != nil {
			log.Errorf("unable to add route %s from server, got: %v", newRoute.ID, err)
			continue
		}
		m.routes[id] = newRoute
	}

	if len(m.routes) > 0 {
		err := enableIPForwarding()
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *defaultServerRouter) removeFromServerNetwork(route *route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not removing from server network because context is done")
		return m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()
		err := m.firewall.RemoveRoutingRules(routeToRouterPair(m.wgInterface.Address().String(), route))
		if err != nil {
			return err
		}
		delete(m.routes, route.ID)
		return nil
	}
}

func (m *defaultServerRouter) addToServerNetwork(route *route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not adding to server network because context is done")
		return m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()
		err := m.firewall.InsertRoutingRules(routeToRouterPair(m.wgInterface.Address().String(), route))
		if err != nil {
			return err
		}
		m.routes[route.ID] = route
		return nil
	}
}

func (m *defaultServerRouter) cleanUp() {
	m.mux.Lock()
	defer m.mux.Unlock()
	for _, r := range m.routes {
		err := m.firewall.RemoveRoutingRules(routeToRouterPair(m.wgInterface.Address().String(), r))
		if err != nil {
			log.Warnf("failed to remove clean up route: %s", r.ID)
		}
	}
}

func routeToRouterPair(source string, route *route.Route) firewall.RouterPair {
	parsed := netip.MustParsePrefix(source).Masked()
	return firewall.RouterPair{
		ID:          route.ID,
		Source:      parsed.String(),
		Destination: route.Network.Masked().String(),
		Masquerade:  route.Masquerade,
	}
}
