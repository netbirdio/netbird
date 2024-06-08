//go:build !android

package routemanager

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

type defaultServerRouter struct {
	mux            sync.Mutex
	ctx            context.Context
	routes         map[route.ID]*route.Route
	firewall       firewall.Manager
	wgInterface    *iface.WGIface
	statusRecorder *peer.Status
}

func newServerRouter(ctx context.Context, wgInterface *iface.WGIface, firewall firewall.Manager, statusRecorder *peer.Status) (serverRouter, error) {
	return &defaultServerRouter{
		ctx:            ctx,
		routes:         make(map[route.ID]*route.Route),
		firewall:       firewall,
		wgInterface:    wgInterface,
		statusRecorder: statusRecorder,
	}, nil
}

func (m *defaultServerRouter) updateRoutes(routesMap map[route.ID]*route.Route) error {
	serverRoutesToRemove := make([]route.ID, 0)

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
			log.Errorf("Unable to remove route id: %s, network %s, from server, got: %v",
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
			log.Errorf("Unable to add route %s from server, got: %v", newRoute.ID, err)
			continue
		}
		m.routes[id] = newRoute
	}

	if len(m.routes) > 0 {
		err := enableIPForwarding(m.wgInterface.Address6() != nil)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *defaultServerRouter) removeFromServerNetwork(rt *route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("Not removing from server network because context is done")
		return m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()
		routingAddress := m.wgInterface.Address().Masked().String()
		if rt.NetworkType == route.IPv6Network {
			if m.wgInterface.Address6() == nil {
				return fmt.Errorf("attempted to add route for IPv6 even though device has no v6 address")
			}
			routingAddress = m.wgInterface.Address6().Masked().String()
		}
		routerPair, err := routeToRouterPair(routingAddress, rt)
		if err != nil {
			return fmt.Errorf("parse prefix: %w", err)
		}
		err = m.firewall.RemoveRoutingRules(routerPair)
		if err != nil {
			return err
		}

		delete(m.routes, rt.ID)

		state := m.statusRecorder.GetLocalPeerState()
		delete(state.Routes, rt.Network.String())
		m.statusRecorder.UpdateLocalPeerState(state)
		return nil
	}
}

func (m *defaultServerRouter) addToServerNetwork(rt *route.Route) error {
	select {
	case <-m.ctx.Done():
		log.Infof("Not adding to server network because context is done")
		return m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()
		routingAddress := m.wgInterface.Address().Masked().String()
		if rt.NetworkType == route.IPv6Network {
			if m.wgInterface.Address6() == nil {
				return fmt.Errorf("attempted to add route for IPv6 even though device has no v6 address")
			}
			routingAddress = m.wgInterface.Address6().Masked().String()
		}

		routerPair, err := routeToRouterPair(routingAddress, rt)
		if err != nil {
			return fmt.Errorf("parse prefix: %w", err)
		}

		err = m.firewall.InsertRoutingRules(routerPair)
		if err != nil {
			return fmt.Errorf("insert routing rules: %w", err)
		}

		m.routes[rt.ID] = rt

		state := m.statusRecorder.GetLocalPeerState()
		if state.Routes == nil {
			state.Routes = map[string]struct{}{}
		}
		state.Routes[rt.Network.String()] = struct{}{}
		m.statusRecorder.UpdateLocalPeerState(state)

		return nil
	}
}

func (m *defaultServerRouter) cleanUp() {
	m.mux.Lock()
	defer m.mux.Unlock()
	for _, r := range m.routes {
		routingAddress := m.wgInterface.Address().Masked().String()
		if r.NetworkType == route.IPv6Network {
			if m.wgInterface.Address6() == nil {
				log.Errorf("attempted to remove route for IPv6 even though device has no v6 address")
				continue
			}
			routingAddress = m.wgInterface.Address6().Masked().String()
		}
		routerPair, err := routeToRouterPair(routingAddress, r)
		if err != nil {
			log.Errorf("parse prefix: %v", err)
		}

		err = m.firewall.RemoveRoutingRules(routerPair)
		if err != nil {
			log.Errorf("Failed to remove cleanup route: %v", err)
		}

	}

	state := m.statusRecorder.GetLocalPeerState()
	state.Routes = nil
	m.statusRecorder.UpdateLocalPeerState(state)
}

func routeToRouterPair(source string, route *route.Route) (firewall.RouterPair, error) {
	parsed, err := netip.ParsePrefix(source)
	if err != nil {
		return firewall.RouterPair{}, err
	}
	return firewall.RouterPair{
		ID:          string(route.ID),
		Source:      parsed.String(),
		Destination: route.Network.Masked().String(),
		Masquerade:  route.Masquerade,
	}, nil
}
