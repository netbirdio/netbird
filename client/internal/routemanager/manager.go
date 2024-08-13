package routemanager

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
	nbnet "github.com/netbirdio/netbird/util/net"
	"github.com/netbirdio/netbird/version"
)

var defaultv4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)

// nolint:unused
var defaultv6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

// Manager is a route manager interface
type Manager interface {
	Init() (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error)
	UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap, error)
	TriggerSelection(route.HAMap)
	GetRouteSelector() *routeselector.RouteSelector
	SetRouteChangeListener(listener listener.NetworkChangeListener)
	InitialRouteRange() []string
	ResetV6Routes()
	EnableServerRouter(firewall firewall.Manager) error
	Stop()
}

// DefaultManager is the default instance of a route manager
type DefaultManager struct {
	ctx            context.Context
	stop           context.CancelFunc
	mux            sync.Mutex
	clientNetworks map[route.HAUniqueID]*clientNetwork
	routeSelector  *routeselector.RouteSelector
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
		clientNetworks: make(map[route.HAUniqueID]*clientNetwork),
		routeSelector:  routeselector.NewRouteSelector(),
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

// Init sets up the routing
func (m *DefaultManager) Init() (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	if nbnet.CustomRoutingDisabled() {
		return nil, nil, nil
	}

	if err := cleanupRouting(); err != nil {
		log.Warnf("Failed cleaning up routing: %v", err)
	}

	mgmtAddress := m.statusRecorder.GetManagementState().URL
	signalAddress := m.statusRecorder.GetSignalState().URL
	ips := resolveURLsToIPs([]string{mgmtAddress, signalAddress})

	beforePeerHook, afterPeerHook, err := setupRouting(ips, m.wgInterface)
	if err != nil {
		return nil, nil, fmt.Errorf("setup routing: %w", err)
	}
	log.Info("Routing setup complete")
	return beforePeerHook, afterPeerHook, nil
}

func (m *DefaultManager) EnableServerRouter(firewall firewall.Manager) error {
	var err error
	m.serverRouter, err = newServerRouter(m.ctx, m.wgInterface, firewall, m.statusRecorder)
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

	if !nbnet.CustomRoutingDisabled() {
		if err := cleanupRouting(); err != nil {
			log.Errorf("Error cleaning up routing: %v", err)
		} else {
			log.Info("Routing cleanup complete")
		}
	}

	m.ctx = nil
}

// UpdateRoutes compares received routes with existing routes and removes, updates or adds them to the client and server maps
func (m *DefaultManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap, error) {
	select {
	case <-m.ctx.Done():
		log.Infof("not updating routes as context is closed")
		return nil, nil, m.ctx.Err()
	default:
		m.mux.Lock()
		defer m.mux.Unlock()

		newServerRoutesMap, newClientRoutesIDMap := m.classifyRoutes(newRoutes)

		filteredClientRoutes := m.routeSelector.FilterSelected(newClientRoutesIDMap)
		m.updateClientNetworks(updateSerial, filteredClientRoutes)
		m.notifier.onNewRoutes(filteredClientRoutes)

		if m.serverRouter != nil {
			err := m.serverRouter.updateRoutes(newServerRoutesMap)
			if err != nil {
				return nil, nil, fmt.Errorf("update routes: %w", err)
			}
		}

		return newServerRoutesMap, newClientRoutesIDMap, nil
	}
}

// ResetV6Routes deletes all IPv6 routes (necessary if IPv6 address changes).
// It is expected that UpdateRoute is called afterwards to recreate the routing table.
func (m *DefaultManager) ResetV6Routes() {
	for id, client := range m.clientNetworks {
		if client.network.Addr().Is6() {
			log.Debugf("stopping client network watcher due to IPv6 address change, %s", id)
			client.stop()
			delete(m.clientNetworks, id)
		}
	}
}

// SetRouteChangeListener set RouteListener for route change notifier
func (m *DefaultManager) SetRouteChangeListener(listener listener.NetworkChangeListener) {
	m.notifier.setListener(listener)
}

// InitialRouteRange return the list of initial routes. It used by mobile systems
func (m *DefaultManager) InitialRouteRange() []string {
	return m.notifier.getInitialRouteRanges()
}

// GetRouteSelector returns the route selector
func (m *DefaultManager) GetRouteSelector() *routeselector.RouteSelector {
	return m.routeSelector
}

// GetClientRoutes returns the client routes
func (m *DefaultManager) GetClientRoutes() map[route.HAUniqueID]*clientNetwork {
	return m.clientNetworks
}

// TriggerSelection triggers the selection of routes, stopping deselected watchers and starting newly selected ones
func (m *DefaultManager) TriggerSelection(networks route.HAMap) {
	m.mux.Lock()
	defer m.mux.Unlock()

	networks = m.routeSelector.FilterSelected(networks)

	m.notifier.onNewRoutes(networks)

	m.stopObsoleteClients(networks)

	for id, routes := range networks {
		if _, found := m.clientNetworks[id]; found {
			// don't touch existing client network watchers
			continue
		}

		clientNetworkWatcher := newClientNetworkWatcher(m.ctx, m.wgInterface, m.statusRecorder, routes[0].Network)
		m.clientNetworks[id] = clientNetworkWatcher
		go clientNetworkWatcher.peersStateAndUpdateWatcher()
		clientNetworkWatcher.sendUpdateToClientNetworkWatcher(routesUpdate{routes: routes})
	}
}

// stopObsoleteClients stops the client network watcher for the networks that are not in the new list
func (m *DefaultManager) stopObsoleteClients(networks route.HAMap) {
	for id, client := range m.clientNetworks {
		if _, ok := networks[id]; !ok {
			log.Debugf("Stopping client network watcher, %s", id)
			client.stop()
			delete(m.clientNetworks, id)
		}
	}
}

func (m *DefaultManager) updateClientNetworks(updateSerial uint64, networks route.HAMap) {
	// removing routes that do not exist as per the update from the Management service.
	m.stopObsoleteClients(networks)

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

func (m *DefaultManager) classifyRoutes(newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap) {
	newClientRoutesIDMap := make(route.HAMap)
	newServerRoutesMap := make(map[route.ID]*route.Route)
	ownNetworkIDs := make(map[route.HAUniqueID]bool)

	for _, newRoute := range newRoutes {
		haID := route.GetHAUniqueID(newRoute)
		if newRoute.Peer == m.pubKey {
			ownNetworkIDs[haID] = true
			// only linux is supported for now
			if runtime.GOOS != "linux" {
				log.Warnf("received a route to manage, but agent doesn't support router mode on %s OS", runtime.GOOS)
				continue
			}
			newServerRoutesMap[newRoute.ID] = newRoute
		}
	}

	for _, newRoute := range newRoutes {
		haID := route.GetHAUniqueID(newRoute)
		if !ownNetworkIDs[haID] {
			if !isPrefixSupported(newRoute.Network) {
				continue
			}
			newClientRoutesIDMap[haID] = append(newClientRoutesIDMap[haID], newRoute)
		}
	}

	return newServerRoutesMap, newClientRoutesIDMap
}

func (m *DefaultManager) clientRoutes(initialRoutes []*route.Route) []*route.Route {
	_, crMap := m.classifyRoutes(initialRoutes)
	rs := make([]*route.Route, 0)
	for _, routes := range crMap {
		rs = append(rs, routes...)
	}
	return rs
}

func isPrefixSupported(prefix netip.Prefix) bool {
	if !nbnet.CustomRoutingDisabled() {
		return true
	}

	// If prefix is too small, lets assume it is a possible default prefix which is not yet supported
	// we skip this prefix management
	if prefix.Bits() <= minRangeBits {
		log.Warnf("This agent version: %s, doesn't support default routes, received %s, skipping this prefix",
			version.NetbirdVersion(), prefix)
		return false
	}
	return true
}

// resolveURLsToIPs takes a slice of URLs, resolves them to IP addresses and returns a slice of IPs.
func resolveURLsToIPs(urls []string) []net.IP {
	var ips []net.IP
	for _, rawurl := range urls {
		u, err := url.Parse(rawurl)
		if err != nil {
			log.Errorf("Failed to parse url %s: %v", rawurl, err)
			continue
		}
		ipAddrs, err := net.LookupIP(u.Hostname())
		if err != nil {
			log.Errorf("Failed to resolve host %s: %v", u.Hostname(), err)
			continue
		}
		ips = append(ips, ipAddrs...)
	}
	return ips
}
