package routemanager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/fakeip"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/server"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	"github.com/netbirdio/netbird/version"
)

// Manager is a route manager interface
type Manager interface {
	Init() error
	UpdateRoutes(updateSerial uint64, serverRoutes map[route.ID]*route.Route, clientRoutes route.HAMap, useNewDNSRoute bool) error
	ClassifyRoutes(newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap)
	TriggerSelection(route.HAMap)
	GetRouteSelector() *routeselector.RouteSelector
	GetClientRoutes() route.HAMap
	GetClientRoutesWithNetID() map[route.NetID][]*route.Route
	SetRouteChangeListener(listener listener.NetworkChangeListener)
	InitialRouteRange() []string
	SetFirewall(firewall.Manager) error
	SetDNSForwarderPort(port uint16)
	Stop(stateManager *statemanager.Manager)
}

type ManagerConfig struct {
	Context             context.Context
	PublicKey           string
	DNSRouteInterval    time.Duration
	WGInterface         iface.WGIface
	StatusRecorder      *peer.Status
	RelayManager        *relayClient.Manager
	InitialRoutes       []*route.Route
	StateManager        *statemanager.Manager
	DNSServer           dns.Server
	DNSFeatureFlag      bool
	PeerStore           *peerstore.Store
	DisableClientRoutes bool
	DisableServerRoutes bool
}

// DefaultManager is the default instance of a route manager
type DefaultManager struct {
	ctx                  context.Context
	stop                 context.CancelFunc
	mux                  sync.Mutex
	shutdownWg           sync.WaitGroup
	clientNetworks       map[route.HAUniqueID]*client.Watcher
	routeSelector        *routeselector.RouteSelector
	serverRouter         *server.Router
	sysOps               *systemops.SysOps
	statusRecorder       *peer.Status
	relayMgr             *relayClient.Manager
	wgInterface          iface.WGIface
	pubKey               string
	notifier             *notifier.Notifier
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefCounter *refcounter.AllowedIPsRefCounter
	dnsRouteInterval     time.Duration
	stateManager         *statemanager.Manager
	// clientRoutes is the most recent list of clientRoutes received from the Management Service
	clientRoutes        route.HAMap
	dnsServer           dns.Server
	firewall            firewall.Manager
	peerStore           *peerstore.Store
	useNewDNSRoute      bool
	disableClientRoutes bool
	disableServerRoutes bool
	activeRoutes        map[route.HAUniqueID]client.RouteHandler
	fakeIPManager       *fakeip.Manager
	dnsForwarderPort    atomic.Uint32
}

func NewManager(config ManagerConfig) *DefaultManager {
	mCTX, cancel := context.WithCancel(config.Context)
	notifier := notifier.NewNotifier()
	sysOps := systemops.New(config.WGInterface, notifier)

	if runtime.GOOS == "windows" && config.WGInterface != nil {
		nbnet.SetVPNInterfaceName(config.WGInterface.Name())
	}

	dm := &DefaultManager{
		ctx:                 mCTX,
		stop:                cancel,
		dnsRouteInterval:    config.DNSRouteInterval,
		clientNetworks:      make(map[route.HAUniqueID]*client.Watcher),
		relayMgr:            config.RelayManager,
		sysOps:              sysOps,
		statusRecorder:      config.StatusRecorder,
		wgInterface:         config.WGInterface,
		pubKey:              config.PublicKey,
		notifier:            notifier,
		stateManager:        config.StateManager,
		dnsServer:           config.DNSServer,
		peerStore:           config.PeerStore,
		disableClientRoutes: config.DisableClientRoutes,
		disableServerRoutes: config.DisableServerRoutes,
		activeRoutes:        make(map[route.HAUniqueID]client.RouteHandler),
	}
	dm.dnsForwarderPort.Store(uint32(nbdns.ForwarderClientPort))

	useNoop := netstack.IsEnabled() || config.DisableClientRoutes
	dm.setupRefCounters(useNoop)

	// don't proceed with client routes if it is disabled
	if config.DisableClientRoutes {
		return dm
	}

	if runtime.GOOS == "android" {
		dm.setupAndroidRoutes(config)
	}
	return dm
}
func (m *DefaultManager) setupAndroidRoutes(config ManagerConfig) {
	cr := m.initialClientRoutes(config.InitialRoutes)

	routesForComparison := slices.Clone(cr)

	if config.DNSFeatureFlag {
		m.fakeIPManager = fakeip.NewManager()

		id := uuid.NewString()
		fakeIPRoute := &route.Route{
			ID:          route.ID(id),
			Network:     m.fakeIPManager.GetFakeIPBlock(),
			NetID:       route.NetID(id),
			Peer:        m.pubKey,
			NetworkType: route.IPv4Network,
		}
		cr = append(cr, fakeIPRoute)
	}

	m.notifier.SetInitialClientRoutes(cr, routesForComparison)
}

func (m *DefaultManager) setupRefCounters(useNoop bool) {
	var once sync.Once
	var wgIface *net.Interface
	toInterface := func() *net.Interface {
		once.Do(func() {
			wgIface = m.wgInterface.ToInterface()
		})
		return wgIface
	}

	m.routeRefCounter = refcounter.New(
		func(prefix netip.Prefix, _ struct{}) (struct{}, error) {
			return struct{}{}, m.sysOps.AddVPNRoute(prefix, toInterface())
		},
		func(prefix netip.Prefix, _ struct{}) error {
			return m.sysOps.RemoveVPNRoute(prefix, toInterface())
		},
	)

	if useNoop {
		m.routeRefCounter = refcounter.New(
			func(netip.Prefix, struct{}) (struct{}, error) {
				return struct{}{}, refcounter.ErrIgnore
			},
			func(netip.Prefix, struct{}) error {
				return nil
			},
		)
	}

	m.allowedIPsRefCounter = refcounter.New(
		func(prefix netip.Prefix, peerKey string) (string, error) {
			// save peerKey to use it in the remove function
			return peerKey, m.wgInterface.AddAllowedIP(peerKey, prefix)
		},
		func(prefix netip.Prefix, peerKey string) error {
			if err := m.wgInterface.RemoveAllowedIP(peerKey, prefix); err != nil {
				if !errors.Is(err, configurer.ErrPeerNotFound) && !errors.Is(err, configurer.ErrAllowedIPNotFound) {
					return err
				}
				log.Tracef("Remove allowed IPs %s for %s: %v", prefix, peerKey, err)
			}
			return nil
		},
	)
}

// Init sets up the routing
func (m *DefaultManager) Init() error {
	m.routeSelector = m.initSelector()

	if nbnet.CustomRoutingDisabled() || m.disableClientRoutes {
		return nil
	}

	if err := m.sysOps.CleanupRouting(nil, nbnet.AdvancedRouting()); err != nil {
		log.Warnf("Failed cleaning up routing: %v", err)
	}

	initialAddresses := []string{m.statusRecorder.GetManagementState().URL, m.statusRecorder.GetSignalState().URL}
	if m.relayMgr != nil {
		initialAddresses = append(initialAddresses, m.relayMgr.ServerURLs()...)
	}

	ips := resolveURLsToIPs(initialAddresses)

	if err := m.sysOps.SetupRouting(ips, m.stateManager, nbnet.AdvancedRouting()); err != nil {
		return fmt.Errorf("setup routing: %w", err)
	}

	log.Info("Routing setup complete")
	return nil
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

// SetFirewall sets the firewall manager for the DefaultManager
// Not thread-safe, should be called before starting the manager
func (m *DefaultManager) SetFirewall(firewall firewall.Manager) error {
	m.firewall = firewall

	if m.disableServerRoutes || firewall == nil {
		log.Info("server routes are disabled")
		return nil
	}

	var err error
	m.serverRouter, err = server.NewRouter(m.ctx, m.wgInterface, firewall, m.statusRecorder)
	if err != nil {
		return err
	}
	return nil
}

// SetDNSForwarderPort sets the DNS forwarder port for route handlers
func (m *DefaultManager) SetDNSForwarderPort(port uint16) {
	m.dnsForwarderPort.Store(uint32(port))
}

// Stop stops the manager watchers and clean firewall rules
func (m *DefaultManager) Stop(stateManager *statemanager.Manager) {
	m.stop()
	m.shutdownWg.Wait()
	if m.serverRouter != nil {
		m.serverRouter.CleanUp()
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

	if !nbnet.CustomRoutingDisabled() && !m.disableClientRoutes {
		if err := m.sysOps.CleanupRouting(stateManager, nbnet.AdvancedRouting()); err != nil {
			log.Errorf("Error cleaning up routing: %v", err)
		} else {
			log.Info("Routing cleanup complete")
		}

		if runtime.GOOS == "windows" {
			nbnet.SetVPNInterfaceName("")
		}
	}

	m.mux.Lock()
	defer m.mux.Unlock()
	m.clientRoutes = nil
}

// UpdateRoutes compares received routes with existing routes and removes, updates or adds them to the client and server maps
func (m *DefaultManager) updateSystemRoutes(newRoutes route.HAMap) error {
	toAdd := make(map[route.HAUniqueID]*route.Route)
	toRemove := make(map[route.HAUniqueID]client.RouteHandler)

	for id, routes := range newRoutes {
		if len(routes) > 0 {
			toAdd[id] = routes[0]
		}
	}

	for id, activeHandler := range m.activeRoutes {
		if _, exists := toAdd[id]; exists {
			delete(toAdd, id)
		} else {
			toRemove[id] = activeHandler
		}
	}

	var merr *multierror.Error
	for id, handler := range toRemove {
		if err := handler.RemoveRoute(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove route %s: %w", handler.String(), err))
		}
		delete(m.activeRoutes, id)
	}

	for id, route := range toAdd {
		params := common.HandlerParams{
			Route:                route,
			RouteRefCounter:      m.routeRefCounter,
			AllowedIPsRefCounter: m.allowedIPsRefCounter,
			DnsRouterInterval:    m.dnsRouteInterval,
			StatusRecorder:       m.statusRecorder,
			WgInterface:          m.wgInterface,
			DnsServer:            m.dnsServer,
			PeerStore:            m.peerStore,
			UseNewDNSRoute:       m.useNewDNSRoute,
			Firewall:             m.firewall,
			FakeIPManager:        m.fakeIPManager,
			ForwarderPort:        &m.dnsForwarderPort,
		}
		handler := client.HandlerFromRoute(params)
		if err := handler.AddRoute(m.ctx); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add route %s: %w", handler.String(), err))
			continue
		}
		m.activeRoutes[id] = handler
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (m *DefaultManager) UpdateRoutes(
	updateSerial uint64,
	serverRoutes map[route.ID]*route.Route,
	clientRoutes route.HAMap,
	useNewDNSRoute bool,
) error {
	select {
	case <-m.ctx.Done():
		log.Infof("not updating routes as context is closed")
		return nil
	default:
	}

	m.mux.Lock()
	defer m.mux.Unlock()
	m.useNewDNSRoute = useNewDNSRoute

	var merr *multierror.Error
	if !m.disableClientRoutes {

		// Update route selector based on management server's isSelected status
		m.updateRouteSelectorFromManagement(clientRoutes)

		filteredClientRoutes := m.routeSelector.FilterSelectedExitNodes(clientRoutes)

		if err := m.updateSystemRoutes(filteredClientRoutes); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("update system routes: %w", err))
		}

		m.updateClientNetworks(updateSerial, filteredClientRoutes)
		m.notifier.OnNewRoutes(filteredClientRoutes)
	}
	m.clientRoutes = clientRoutes

	if m.serverRouter == nil {
		return nberrors.FormatErrorOrNil(merr)
	}

	if err := m.serverRouter.UpdateRoutes(serverRoutes, useNewDNSRoute); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("update server routes: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
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

	networks = m.routeSelector.FilterSelectedExitNodes(networks)

	m.notifier.OnNewRoutes(networks)

	if err := m.updateSystemRoutes(networks); err != nil {
		log.Errorf("failed to update system routes during selection: %v", err)
	}

	m.stopObsoleteClients(networks)

	for id, routes := range networks {
		if _, found := m.clientNetworks[id]; found {
			// don't touch existing client network watchers
			continue
		}

		handler := m.activeRoutes[id]
		if handler == nil {
			log.Warnf("no active handler found for route %s", id)
			continue
		}

		config := client.WatcherConfig{
			Context:          m.ctx,
			DNSRouteInterval: m.dnsRouteInterval,
			WGInterface:      m.wgInterface,
			StatusRecorder:   m.statusRecorder,
			Route:            routes[0],
			Handler:          handler,
		}
		clientNetworkWatcher := client.NewWatcher(config)
		m.clientNetworks[id] = clientNetworkWatcher
		m.shutdownWg.Add(1)
		go func() {
			defer m.shutdownWg.Done()
			clientNetworkWatcher.Start()
		}()
		clientNetworkWatcher.SendUpdate(client.RoutesUpdate{Routes: routes})
	}

	if err := m.stateManager.UpdateState((*SelectorState)(m.routeSelector)); err != nil {
		log.Errorf("failed to update state: %v", err)
	}
}

// stopObsoleteClients stops the client network watcher for the networks that are not in the new list
func (m *DefaultManager) stopObsoleteClients(networks route.HAMap) {
	for id, client := range m.clientNetworks {
		if _, ok := networks[id]; !ok {
			client.Stop()
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
			handler := m.activeRoutes[id]
			if handler == nil {
				log.Errorf("No active handler found for route %s", id)
				continue
			}

			config := client.WatcherConfig{
				Context:          m.ctx,
				DNSRouteInterval: m.dnsRouteInterval,
				WGInterface:      m.wgInterface,
				StatusRecorder:   m.statusRecorder,
				Route:            routes[0],
				Handler:          handler,
			}
			clientNetworkWatcher = client.NewWatcher(config)
			m.clientNetworks[id] = clientNetworkWatcher
			m.shutdownWg.Add(1)
			go func() {
				defer m.shutdownWg.Done()
				clientNetworkWatcher.Start()
			}()
		}
		update := client.RoutesUpdate{
			UpdateSerial: updateSerial,
			Routes:       routes,
		}
		clientNetworkWatcher.SendUpdate(update)
	}
}

func (m *DefaultManager) ClassifyRoutes(newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap) {
	newClientRoutesIDMap := make(route.HAMap)
	newServerRoutesMap := make(map[route.ID]*route.Route)
	ownNetworkIDs := make(map[route.HAUniqueID]bool)

	for _, newRoute := range newRoutes {
		haID := newRoute.GetHAUniqueID()
		if newRoute.Peer == m.pubKey {
			ownNetworkIDs[haID] = true
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
	_, crMap := m.ClassifyRoutes(initialRoutes)
	rs := make([]*route.Route, 0, len(crMap))
	for _, routes := range crMap {
		rs = append(rs, routes...)
	}

	return rs
}

func isRouteSupported(route *route.Route) bool {
	if netstack.IsEnabled() || !nbnet.CustomRoutingDisabled() || route.IsDynamic() {
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

// updateRouteSelectorFromManagement updates the route selector based on the isSelected status from the management server
func (m *DefaultManager) updateRouteSelectorFromManagement(clientRoutes route.HAMap) {
	exitNodeInfo := m.collectExitNodeInfo(clientRoutes)
	if len(exitNodeInfo.allIDs) == 0 {
		return
	}

	m.updateExitNodeSelections(exitNodeInfo)
	m.logExitNodeUpdate(exitNodeInfo)
}

type exitNodeInfo struct {
	allIDs               []route.NetID
	selectedByManagement []route.NetID
	userSelected         []route.NetID
	userDeselected       []route.NetID
}

func (m *DefaultManager) collectExitNodeInfo(clientRoutes route.HAMap) exitNodeInfo {
	var info exitNodeInfo

	for haID, routes := range clientRoutes {
		if !m.isExitNodeRoute(routes) {
			continue
		}

		netID := haID.NetID()
		info.allIDs = append(info.allIDs, netID)

		if m.routeSelector.HasUserSelectionForRoute(netID) {
			m.categorizeUserSelection(netID, &info)
		} else {
			m.checkManagementSelection(routes, netID, &info)
		}
	}

	return info
}

func (m *DefaultManager) isExitNodeRoute(routes []*route.Route) bool {
	return len(routes) > 0 && routes[0].Network.String() == vars.ExitNodeCIDR
}

func (m *DefaultManager) categorizeUserSelection(netID route.NetID, info *exitNodeInfo) {
	if m.routeSelector.IsSelected(netID) {
		info.userSelected = append(info.userSelected, netID)
	} else {
		info.userDeselected = append(info.userDeselected, netID)
	}
}

func (m *DefaultManager) checkManagementSelection(routes []*route.Route, netID route.NetID, info *exitNodeInfo) {
	for _, route := range routes {
		if !route.SkipAutoApply {
			info.selectedByManagement = append(info.selectedByManagement, netID)
			break
		}
	}
}

func (m *DefaultManager) updateExitNodeSelections(info exitNodeInfo) {
	routesToDeselect := m.getRoutesToDeselect(info.allIDs)
	m.deselectExitNodes(routesToDeselect)
	m.selectExitNodesByManagement(info.selectedByManagement, info.allIDs)
}

func (m *DefaultManager) getRoutesToDeselect(allIDs []route.NetID) []route.NetID {
	var routesToDeselect []route.NetID
	for _, netID := range allIDs {
		if !m.routeSelector.HasUserSelectionForRoute(netID) {
			routesToDeselect = append(routesToDeselect, netID)
		}
	}
	return routesToDeselect
}

func (m *DefaultManager) deselectExitNodes(routesToDeselect []route.NetID) {
	if len(routesToDeselect) == 0 {
		return
	}

	err := m.routeSelector.DeselectRoutes(routesToDeselect, routesToDeselect)
	if err != nil {
		log.Warnf("Failed to deselect exit nodes: %v", err)
	}
}

func (m *DefaultManager) selectExitNodesByManagement(selectedByManagement []route.NetID, allIDs []route.NetID) {
	if len(selectedByManagement) == 0 {
		return
	}

	err := m.routeSelector.SelectRoutes(selectedByManagement, true, allIDs)
	if err != nil {
		log.Warnf("Failed to select exit nodes: %v", err)
	}
}

func (m *DefaultManager) logExitNodeUpdate(info exitNodeInfo) {
	log.Debugf("Updated route selector: %d exit nodes available, %d selected by management, %d user-selected, %d user-deselected",
		len(info.allIDs), len(info.selectedByManagement), len(info.userSelected), len(info.userDeselected))
}
