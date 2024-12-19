package routemanager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	relayClient "github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/route"
	nbnet "github.com/netbirdio/netbird/util/net"
	"github.com/netbirdio/netbird/version"
)

// Manager is a route manager interface
type Manager interface {
	Init() (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error)
	UpdateRoutes(updateSerial uint64, newRoutes []*route.Route, useNewDNSRoute bool) error
	TriggerSelection(route.HAMap)
	GetRouteSelector() *routeselector.RouteSelector
	GetClientRoutes() route.HAMap
	GetClientRoutesWithNetID() map[route.NetID][]*route.Route
	SetRouteChangeListener(listener listener.NetworkChangeListener)
	InitialRouteRange() []string
	EnableServerRouter(firewall firewall.Manager) error
	Stop(stateManager *statemanager.Manager)
}

// DefaultManager is the default instance of a route manager
type DefaultManager struct {
	ctx                  context.Context
	stop                 context.CancelFunc
	mux                  sync.Mutex
	clientNetworks       map[route.HAUniqueID]*clientNetwork
	routeSelector        *routeselector.RouteSelector
	serverRouter         serverRouter
	sysOps               *systemops.SysOps
	statusRecorder       *peer.Status
	relayMgr             *relayClient.Manager
	wgInterface          iface.IWGIface
	pubKey               string
	notifier             *notifier.Notifier
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter
	dnsRouteInterval     time.Duration
	stateManager         *statemanager.Manager
	// clientRoutes is the most recent list of clientRoutes received from the Management Service
	clientRoutes   route.HAMap
	dnsServer      dns.Server
	peerStore      *peerstore.Store
	useNewDNSRoute bool
}

func NewManager(
	ctx context.Context,
	pubKey string,
	dnsRouteInterval time.Duration,
	wgInterface iface.IWGIface,
	statusRecorder *peer.Status,
	relayMgr *relayClient.Manager,
	initialRoutes []*route.Route,
	stateManager *statemanager.Manager,
	dnsServer dns.Server,
	peerStore *peerstore.Store,
) *DefaultManager {
	mCTX, cancel := context.WithCancel(ctx)
	notifier := notifier.NewNotifier()
	sysOps := systemops.NewSysOps(wgInterface, notifier)

	dm := &DefaultManager{
		ctx:              mCTX,
		stop:             cancel,
		dnsRouteInterval: dnsRouteInterval,
		clientNetworks:   make(map[route.HAUniqueID]*clientNetwork),
		relayMgr:         relayMgr,
		sysOps:           sysOps,
		statusRecorder:   statusRecorder,
		wgInterface:      wgInterface,
		pubKey:           pubKey,
		notifier:         notifier,
		stateManager:     stateManager,
		dnsServer:        dnsServer,
		peerStore:        peerStore,
	}

	dm.routeRefCounter = refcounter.New(
		func(prefix netip.Prefix, _ struct{}) (struct{}, error) {
			return struct{}{}, sysOps.AddVPNRoute(prefix, wgInterface.ToInterface())
		},
		func(prefix netip.Prefix, _ struct{}) error {
			return sysOps.RemoveVPNRoute(prefix, wgInterface.ToInterface())
		},
	)

	dm.allowedIPsRefCounter = refcounter.New(
		func(prefix netip.Prefix, peerKey string) (string, error) {
			// save peerKey to use it in the remove function
			return peerKey, wgInterface.AddAllowedIP(peerKey, prefix.String())
		},
		func(prefix netip.Prefix, peerKey string) error {
			if err := wgInterface.RemoveAllowedIP(peerKey, prefix.String()); err != nil {
				if !errors.Is(err, configurer.ErrPeerNotFound) && !errors.Is(err, configurer.ErrAllowedIPNotFound) {
					return err
				}
				log.Tracef("Remove allowed IPs %s for %s: %v", prefix, peerKey, err)
			}
			return nil
		},
	)

	if runtime.GOOS == "android" {
		cr := dm.initialClientRoutes(initialRoutes)
		dm.notifier.SetInitialClientRoutes(cr)
	}
	return dm
}

// Init sets up the routing
func (m *DefaultManager) Init() (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	m.routeSelector = m.initSelector()

	if nbnet.CustomRoutingDisabled() {
		return nil, nil, nil
	}

	if err := m.sysOps.CleanupRouting(nil); err != nil {
		log.Warnf("Failed cleaning up routing: %v", err)
	}

	initialAddresses := []string{m.statusRecorder.GetManagementState().URL, m.statusRecorder.GetSignalState().URL}
	if m.relayMgr != nil {
		initialAddresses = append(initialAddresses, m.relayMgr.ServerURLs()...)
	}

	ips := resolveURLsToIPs(initialAddresses)

	beforePeerHook, afterPeerHook, err := m.sysOps.SetupRouting(ips, m.stateManager)
	if err != nil {
		return nil, nil, fmt.Errorf("setup routing: %w", err)
	}

	log.Info("Routing setup complete")
	return beforePeerHook, afterPeerHook, nil
}

func (m *DefaultManager) initSelector() *routeselector.RouteSelector {
	var state *SelectorState
	m.stateManager.RegisterState(state)

	// restore selector state if it exists
	if err := m.stateManager.LoadState(state); err != nil {
		log.Warnf("failed to load state: %v", err)
		return routeselector.NewRouteSelector()
	}

	if state := m.stateManager.GetState(state); state != nil {
		if selector, ok := state.(*SelectorState); ok {
			return (*routeselector.RouteSelector)(selector)
		}

		log.Warnf("failed to convert state with type %T to SelectorState", state)
	}

	return routeselector.NewRouteSelector()
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
func (m *DefaultManager) Stop(stateManager *statemanager.Manager) {
	m.stop()
	if m.serverRouter != nil {
		m.serverRouter.cleanUp()
	}

	if m.routeRefCounter != nil {
		if err := m.routeRefCounter.Flush(); err != nil {
			log.Errorf("Error flushing route ref counter: %v", err)
		}
	}
	if m.allowedIPsRefCounter != nil {
		if err := m.allowedIPsRefCounter.Flush(); err != nil {
			log.Errorf("Error flushing allowed IPs ref counter: %v", err)
		}
	}

	if !nbnet.CustomRoutingDisabled() {
		if err := m.sysOps.CleanupRouting(stateManager); err != nil {
			log.Errorf("Error cleaning up routing: %v", err)
		} else {
			log.Info("Routing cleanup complete")
		}
	}

	m.ctx = nil

	m.mux.Lock()
	defer m.mux.Unlock()
	m.clientRoutes = nil
}

// UpdateRoutes compares received routes with existing routes and removes, updates or adds them to the client and server maps
func (m *DefaultManager) UpdateRoutes(updateSerial uint64, newRoutes []*route.Route, useNewDNSRoute bool) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not updating routes as context is closed")
		return nil
	default:
	}

	m.mux.Lock()
	defer m.mux.Unlock()
	m.useNewDNSRoute = useNewDNSRoute

	newServerRoutesMap, newClientRoutesIDMap := m.classifyRoutes(newRoutes)

	filteredClientRoutes := m.routeSelector.FilterSelected(newClientRoutesIDMap)
	m.updateClientNetworks(updateSerial, filteredClientRoutes)
	m.notifier.OnNewRoutes(filteredClientRoutes)

	if m.serverRouter != nil {
		err := m.serverRouter.updateRoutes(newServerRoutesMap)
		if err != nil {
			return err
		}
	}

	m.clientRoutes = newClientRoutesIDMap

	return nil
}

// SetRouteChangeListener set RouteListener for route change Notifier
func (m *DefaultManager) SetRouteChangeListener(listener listener.NetworkChangeListener) {
	m.notifier.SetListener(listener)
}

// InitialRouteRange return the list of initial routes. It used by mobile systems
func (m *DefaultManager) InitialRouteRange() []string {
	return m.notifier.GetInitialRouteRanges()
}

// GetRouteSelector returns the route selector
func (m *DefaultManager) GetRouteSelector() *routeselector.RouteSelector {
	return m.routeSelector
}

// GetClientRoutes returns most recent list of clientRoutes received from the Management Service
func (m *DefaultManager) GetClientRoutes() route.HAMap {
	m.mux.Lock()
	defer m.mux.Unlock()

	return maps.Clone(m.clientRoutes)
}

// GetClientRoutesWithNetID returns the current routes from the route map, but the keys consist of the network ID only
func (m *DefaultManager) GetClientRoutesWithNetID() map[route.NetID][]*route.Route {
	m.mux.Lock()
	defer m.mux.Unlock()

	routes := make(map[route.NetID][]*route.Route, len(m.clientRoutes))
	for id, v := range m.clientRoutes {
		routes[id.NetID()] = v
	}
	return routes
}

// TriggerSelection triggers the selection of routes, stopping deselected watchers and starting newly selected ones
func (m *DefaultManager) TriggerSelection(networks route.HAMap) {
	m.mux.Lock()
	defer m.mux.Unlock()

	networks = m.routeSelector.FilterSelected(networks)

	m.notifier.OnNewRoutes(networks)

	m.stopObsoleteClients(networks)

	for id, routes := range networks {
		if _, found := m.clientNetworks[id]; found {
			// don't touch existing client network watchers
			continue
		}

		clientNetworkWatcher := newClientNetworkWatcher(
			m.ctx,
			m.dnsRouteInterval,
			m.wgInterface,
			m.statusRecorder,
			routes[0],
			m.routeRefCounter,
			m.allowedIPsRefCounter,
			m.dnsServer,
			m.peerStore,
			m.useNewDNSRoute,
		)
		m.clientNetworks[id] = clientNetworkWatcher
		go clientNetworkWatcher.peersStateAndUpdateWatcher()
		clientNetworkWatcher.sendUpdateToClientNetworkWatcher(routesUpdate{routes: routes})
	}

	if err := m.stateManager.UpdateState((*SelectorState)(m.routeSelector)); err != nil {
		log.Errorf("failed to update state: %v", err)
	}
}

// stopObsoleteClients stops the client network watcher for the networks that are not in the new list
func (m *DefaultManager) stopObsoleteClients(networks route.HAMap) {
	for id, client := range m.clientNetworks {
		if _, ok := networks[id]; !ok {
			log.Debugf("Stopping client network watcher, %s", id)
			client.cancel()
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
			clientNetworkWatcher = newClientNetworkWatcher(
				m.ctx,
				m.dnsRouteInterval,
				m.wgInterface,
				m.statusRecorder,
				routes[0],
				m.routeRefCounter,
				m.allowedIPsRefCounter,
				m.dnsServer,
				m.peerStore,
				m.useNewDNSRoute,
			)
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
		haID := newRoute.GetHAUniqueID()
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
		haID := newRoute.GetHAUniqueID()
		if !ownNetworkIDs[haID] {
			if !isRouteSupported(newRoute) {
				continue
			}
			newClientRoutesIDMap[haID] = append(newClientRoutesIDMap[haID], newRoute)
		}
	}

	return newServerRoutesMap, newClientRoutesIDMap
}

func (m *DefaultManager) initialClientRoutes(initialRoutes []*route.Route) []*route.Route {
	_, crMap := m.classifyRoutes(initialRoutes)
	rs := make([]*route.Route, 0, len(crMap))
	for _, routes := range crMap {
		rs = append(rs, routes...)
	}
	return rs
}

func isRouteSupported(route *route.Route) bool {
	if !nbnet.CustomRoutingDisabled() || route.IsDynamic() {
		return true
	}

	// If prefix is too small, lets assume it is a possible default prefix which is not yet supported
	// we skip this prefix management
	if route.Network.Bits() <= vars.MinRangeBits {
		log.Warnf("This agent version: %s, doesn't support default routes, received %s, skipping this prefix",
			version.NetbirdVersion(), route.Network)
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
