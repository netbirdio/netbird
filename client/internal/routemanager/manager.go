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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	GetSelectedClientRoutes() route.HAMap
	GetActiveClientRoutes() route.HAMap
	GetClientRoutesWithNetID() map[route.NetID][]*route.Route
	SetRouteChangeListener(listener listener.NetworkChangeListener)
	InitialRouteRange() []string
	SetFirewall(firewall.Manager) error
	SetDNSForwarderPort(port uint16)
	ReconcilePeerAllowedIPs(peerKey string) error
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

		v4ID := uuid.NewString()
		fakeIPRoute := &route.Route{
			ID:          route.ID(v4ID),
			Network:     m.fakeIPManager.GetFakeIPBlock(),
			NetID:       route.NetID(v4ID),
			Peer:        m.pubKey,
			NetworkType: route.IPv4Network,
		}
		v6ID := uuid.NewString()
		fakeIPv6Route := &route.Route{
			ID:          route.ID(v6ID),
			Network:     m.fakeIPManager.GetFakeIPv6Block(),
			NetID:       route.NetID(v6ID),
			Peer:        m.pubKey,
			NetworkType: route.IPv6Network,
		}
		cr = append(cr, fakeIPRoute, fakeIPv6Route)
		m.notifier.SetFakeIPRoutes([]*route.Route{fakeIPRoute, fakeIPv6Route})
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

// ReconcilePeerAllowedIPs re-applies every routed allowed IP currently tracked for the peer
// onto the WireGuard device. The allowed-IP refcounter only calls its AddFunc (which pushes to
// the device) on a prefix's 0->1 transition, so a peer whose device entry was rebuilt without a
// matching refcounter change — e.g. a lazy connection cycling through idle->wake, which recreates
// the WireGuard peer with the overlay /32 only — ends up missing routed prefixes the refcounter
// still considers installed, and nothing retries. Calling this when the peer's WireGuard entry is
// (re)created restores convergence. It is add-only and idempotent: AddAllowedIP is update-only, so
// prefixes are re-added to an existing peer and an absent peer is left untouched.
func (m *DefaultManager) ReconcilePeerAllowedIPs(peerKey string) error {
	if m.allowedIPsRefCounter == nil {
		return nil
	}

	return m.allowedIPsRefCounter.ReapplyMatching(
		func(out string) bool { return out == peerKey },
		func(prefix netip.Prefix) error {
			if err := m.wgInterface.AddAllowedIP(peerKey, prefix); err != nil {
				return fmt.Errorf("add allowed IP %s for peer %s: %w", prefix, peerKey, err)
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
		if errors.Is(err, syscall.ENOSYS) {
			log.Debugf("route selector state unavailable on this platform: %v", err)
		} else {
			log.Warnf("failed to load state: %v", err)
		}
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

	m.notifier.Close()

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

	// Begin batch mode to avoid calling applyHostConfig() after each DNS handler operation
	batchStarted := false
	if m.dnsServer != nil {
		m.dnsServer.BeginBatch()
		batchStarted = true
		defer func() {
			if merr != nil {
				// On error, cancel batch to discard partial DNS state
				m.dnsServer.CancelBatch()
			} else {
				// On success, apply accumulated DNS changes
				m.dnsServer.EndBatch()
			}
		}()
	}

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

	_ = batchStarted // Mark as used
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
		// A new network map can add or drop route/exit-node candidates without
		// touching any peer's chosen-route state, so the peer status alone
		// wouldn't notify SubscribeStatus subscribers. Bump the revision so the
		// UI re-fetches ListNetworks.
		m.statusRecorder.BumpNetworksRevision()
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

// GetSelectedClientRoutes returns only the currently selected/active client routes,
// filtering out deselected exit nodes. Use this instead of GetClientRoutes when checking
// if traffic should be routed through the tunnel.
func (m *DefaultManager) GetSelectedClientRoutes() route.HAMap {
	m.mux.Lock()
	defer m.mux.Unlock()

	return m.routeSelector.FilterSelectedExitNodes(maps.Clone(m.clientRoutes))
}

// GetActiveClientRoutes returns the subset of selected client routes
// that are currently reachable: the route's peer is Connected and is
// the one actively carrying the route (not just an HA sibling).
func (m *DefaultManager) GetActiveClientRoutes() route.HAMap {
	m.mux.Lock()
	selected := m.routeSelector.FilterSelectedExitNodes(maps.Clone(m.clientRoutes))
	recorder := m.statusRecorder
	m.mux.Unlock()

	if recorder == nil {
		return selected
	}

	out := make(route.HAMap, len(selected))
	for id, routes := range selected {
		for _, r := range routes {
			st, err := recorder.GetPeer(r.Peer)
			if err != nil {
				continue
			}
			if st.ConnStatus != peer.StatusConnected {
				continue
			}
			if _, hasRoute := st.GetRoutes()[r.Network.String()]; !hasRoute {
				continue
			}
			out[id] = routes
			break
		}
	}
	return out
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

	// A selection change flips Network.selected without altering the candidate
	// set, so bump the revision to push the new state to the UI.
	m.statusRecorder.BumpNetworksRevision()
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

// updateRouteSelectorFromManagement reconciles exit-node selection on every
// network map: it keeps at most one exit node selected — the user's persisted
// pick, else whatever management marks for auto-apply (SkipAutoApply=false),
// else none. We never auto-activate an exit node the map doesn't request; it
// stays off until the user picks it. Exit nodes are mutually exclusive, but the
// RouteSelector stores routes with default-on semantics, so without this every
// available exit node would report selected at once.
func (m *DefaultManager) updateRouteSelectorFromManagement(clientRoutes route.HAMap) {
	m.mirrorV6ExitPairSelections(clientRoutes)

	// An explicit user "deselect all" must not be overridden by management auto-apply.
	// Auto-applying an exit node here would call SelectRoutes, which clears the
	// deselect-all flag and re-enables every route the user turned off.
	if m.routeSelector.IsDeselectAll() {
		return
	}

	info := m.collectExitNodeInfo(clientRoutes)
	if len(info.allIDs) == 0 {
		return
	}

	preferred := pickPreferredExitNode(info)
	m.enforceSingleExitNode(preferred, info.allIDs)
	m.logExitNodeUpdate(info, preferred)
}

// mirrorV6ExitPairSelections keeps every synthesized "-v6" exit route's selection
// consistent with its v4 base. The v4/v6 exit pair is a single toggle, so the v6
// entry always follows the base: deselecting the v4 exit node also drops its ::/0
// pair, and any stale (orphaned) explicit selection on the v6 entry is reset. This
// runs before selection is read so both collectExitNodeInfo and FilterSelectedExitNodes
// see consistent state, including pairs loaded from persisted selector state.
func (m *DefaultManager) mirrorV6ExitPairSelections(clientRoutes route.HAMap) {
	routesByNetID := make(map[route.NetID][]*route.Route, len(clientRoutes))
	for haID, routes := range clientRoutes {
		routesByNetID[haID.NetID()] = routes
	}

	for v6ID := range route.V6ExitMergeSet(routesByNetID) {
		baseID := route.NetID(strings.TrimSuffix(string(v6ID), route.V6ExitSuffix))
		m.routeSelector.SyncPairedSelection(baseID, v6ID)
	}
}

type exitNodeInfo struct {
	allIDs               []route.NetID
	selectedByManagement []route.NetID
	userSelected         []route.NetID
	userDeselected       []route.NetID
}

// collectExitNodeInfo categorises the available exit nodes by their persisted
// selection state. It keys on the base (v4) NetID and skips the synthesized
// "-v6" partner, which inherits its base's selection through the RouteSelector
// — counting it separately would double-count the pair.
func (m *DefaultManager) collectExitNodeInfo(clientRoutes route.HAMap) exitNodeInfo {
	var info exitNodeInfo

	for haID, routes := range clientRoutes {
		if !m.isExitNodeRoute(routes) {
			continue
		}

		netID := haID.NetID()
		if strings.HasSuffix(string(netID), route.V6ExitSuffix) {
			continue
		}
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
	if len(routes) == 0 {
		return false
	}
	return route.IsV4DefaultRoute(routes[0].Network) || route.IsV6DefaultRoute(routes[0].Network)
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

// pickPreferredExitNode chooses the single exit node to keep selected. In order:
//   - a persisted user selection wins (deterministic if several survive from
//     legacy state, so the set self-heals down to one);
//   - otherwise activate only what management marks for auto-apply
//     (SkipAutoApply=false); the lexicographically first if it marks several.
//
// Returns "" when neither holds — we never force an arbitrary exit node on. A
// route the map doesn't auto-apply stays off until the user selects it.
// info.userDeselected is informational only: an explicit deselect simply keeps
// that route out of both lists above, so it can't be picked.
func pickPreferredExitNode(info exitNodeInfo) route.NetID {
	if len(info.userSelected) > 0 {
		return minNetID(info.userSelected)
	}
	if len(info.selectedByManagement) > 0 {
		return minNetID(info.selectedByManagement)
	}
	return ""
}

// enforceSingleExitNode makes preferred the only selected exit node: every other
// available exit node is deselected and preferred (if any) is selected, without
// disturbing non-exit route selections. The whole reconciliation runs under a
// single RouteSelector lock (SetExclusiveExitNode) so a concurrent deselect-all
// cannot interleave and get undone; a global deselect-all is left untouched so
// the user's "all off" stays in effect.
func (m *DefaultManager) enforceSingleExitNode(preferred route.NetID, allIDs []route.NetID) {
	m.routeSelector.SetExclusiveExitNode(preferred, allIDs)
}

func (m *DefaultManager) logExitNodeUpdate(info exitNodeInfo, preferred route.NetID) {
	log.Debugf("Exit node selection: %d available, preferred=%q (%d user-selected, %d user-deselected, %d management-selected)",
		len(info.allIDs), preferred, len(info.userSelected), len(info.userDeselected), len(info.selectedByManagement))
}

// minNetID returns the lexicographically smallest NetID, for a deterministic
// default pick that stays stable across restarts.
func minNetID(ids []route.NetID) route.NetID {
	if len(ids) == 0 {
		return ""
	}
	best := ids[0]
	for _, id := range ids[1:] {
		if id < best {
			best = id
		}
	}
	return best
}
