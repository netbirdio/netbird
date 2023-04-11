//go:build !android

package routemanager

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

type serverRouter struct {
	mux         sync.Mutex
	ctx         context.Context
	routes      map[string]*route.Route
	firewall    firewallManager
	wgInterface *iface.WGIface
}

func newServerRouter(ctx context.Context, wgInterface *iface.WGIface) *serverRouter {
	return &serverRouter{
		ctx:         ctx,
		routes:      make(map[string]*route.Route),
		firewall:    NewFirewall(ctx),
		wgInterface: wgInterface,
	}
}

func (m *serverRouter) updateRoutes(routesMap map[string]*route.Route) error {
	serverRoutesToRemove := make([]string, 0)

	if len(routesMap) > 0 {
		err := m.firewall.RestoreOrCreateContainers()
		if err != nil {
			return fmt.Errorf("couldn't initialize firewall containers, got err: %v", err)
		}
	}

	for routeID := range m.routes {
		update, found := routesMap[routeID]
		if !found || !update.IsEqual(m.routes[routeID]) {
			serverRoutesToRemove = append(serverRoutesToRemove, routeID)
			continue
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

func (m *serverRouter) removeFromServerNetwork(route *route.Route) error {
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

func (m *serverRouter) addToServerNetwork(route *route.Route) error {
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

func (m *serverRouter) cleanUp() {
	m.firewall.CleanRoutingRules()
}
