package server

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/route"
)

type Router struct {
	mux            sync.Mutex
	ctx            context.Context
	routes         map[route.ID]*route.Route
	firewall       firewall.Manager
	wgInterface    iface.WGIface
	statusRecorder *peer.Status
}

func NewRouter(ctx context.Context, wgInterface iface.WGIface, firewall firewall.Manager, statusRecorder *peer.Status) (*Router, error) {
	return &Router{
		ctx:            ctx,
		routes:         make(map[route.ID]*route.Route),
		firewall:       firewall,
		wgInterface:    wgInterface,
		statusRecorder: statusRecorder,
	}, nil
}

func (r *Router) UpdateRoutes(routesMap map[route.ID]*route.Route, useNewDNSRoute bool) error {
	r.mux.Lock()
	defer r.mux.Unlock()

	serverRoutesToRemove := make([]route.ID, 0)

	for routeID := range r.routes {
		update, found := routesMap[routeID]
		if !found || !update.Equal(r.routes[routeID]) {
			serverRoutesToRemove = append(serverRoutesToRemove, routeID)
		}
	}

	for _, routeID := range serverRoutesToRemove {
		oldRoute := r.routes[routeID]
		err := r.removeFromServerNetwork(oldRoute)
		if err != nil {
			log.Errorf("Unable to remove route id: %s, network %s, from server, got: %v",
				oldRoute.ID, oldRoute.Network, err)
		}
		delete(r.routes, routeID)
	}

	// If routing is to be disabled, do it after routes have been removed
	// If routing is to be enabled, do it before adding new routes; addToServerNetwork needs routing to be enabled
	if len(routesMap) > 0 {
		if err := r.firewall.EnableRouting(); err != nil {
			return fmt.Errorf("enable routing: %w", err)
		}
	} else {
		if err := r.firewall.DisableRouting(); err != nil {
			return fmt.Errorf("disable routing: %w", err)
		}
	}

	for id, newRoute := range routesMap {
		_, found := r.routes[id]
		if found {
			continue
		}

		err := r.addToServerNetwork(newRoute, useNewDNSRoute)
		if err != nil {
			log.Errorf("Unable to add route %s from server, got: %v", newRoute.ID, err)
			continue
		}
		r.routes[id] = newRoute
	}

	return nil
}

func (r *Router) removeFromServerNetwork(route *route.Route) error {
	if r.ctx.Err() != nil {
		log.Infof("Not removing from server network because context is done")
		return r.ctx.Err()
	}

	routerPair := routeToRouterPair(route, false)
	if err := r.firewall.RemoveNatRule(routerPair); err != nil {
		return fmt.Errorf("remove routing rules: %w", err)
	}

	delete(r.routes, route.ID)
	r.statusRecorder.RemoveLocalPeerStateRoute(route.NetString())

	return nil
}

func (r *Router) addToServerNetwork(route *route.Route, useNewDNSRoute bool) error {
	if r.ctx.Err() != nil {
		log.Infof("Not adding to server network because context is done")
		return r.ctx.Err()
	}

	routerPair := routeToRouterPair(route, useNewDNSRoute)
	if err := r.firewall.AddNatRule(routerPair); err != nil {
		return fmt.Errorf("insert routing rules: %w", err)
	}

	r.routes[route.ID] = route
	r.statusRecorder.AddLocalPeerStateRoute(route.NetString(), route.GetResourceID())

	return nil
}

func (r *Router) CleanUp() {
	r.mux.Lock()
	defer r.mux.Unlock()

	for _, route := range r.routes {
		routerPair := routeToRouterPair(route, false)
		if err := r.firewall.RemoveNatRule(routerPair); err != nil {
			log.Errorf("Failed to remove cleanup route: %v", err)
		}
	}

	r.statusRecorder.CleanLocalPeerStateRoutes()
}

func (r *Router) RoutesCount() int {
	r.mux.Lock()
	defer r.mux.Unlock()
	return len(r.routes)
}

func routeToRouterPair(route *route.Route, useNewDNSRoute bool) firewall.RouterPair {
	source := getDefaultPrefix(route.Network)
	destination := firewall.Network{}
	if route.IsDynamic() {
		if useNewDNSRoute {
			destination.Set = firewall.NewDomainSet(route.Domains)
		} else {
			// TODO: add ipv6 additionally
			destination = getDefaultPrefix(destination.Prefix)
		}
	} else {
		destination.Prefix = route.Network.Masked()
	}

	return firewall.RouterPair{
		ID:          route.ID,
		Source:      source,
		Destination: destination,
		Masquerade:  route.Masquerade,
	}
}

func getDefaultPrefix(prefix netip.Prefix) firewall.Network {
	if prefix.Addr().Is6() {
		return firewall.Network{
			Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		}
	}
	return firewall.Network{
		Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
	}
}
