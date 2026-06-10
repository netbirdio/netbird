package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mitchellh/hashstructure/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/iface/netstack"
	dnsconfig "github.com/netbirdio/netbird/client/internal/dns/config"
	"github.com/netbirdio/netbird/client/internal/dns/local"
	"github.com/netbirdio/netbird/client/internal/dns/mgmt"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/proto"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

const (
	// healthLookback must exceed the upstream query timeout so one
	// query per refresh cycle is enough to keep a group marked healthy.
	healthLookback               = 60 * time.Second
	nsGroupHealthRefreshInterval = 10 * time.Second
	// defaultWarningDelayBase is the starting grace window before a
	// "Nameserver group unreachable" event fires for a group that's
	// never been healthy and only has overlay upstreams with no
	// Connected peer. Per-server and overridable via envWarningDelay;
	// see warningDelay.
	defaultWarningDelayBase = 60 * time.Second
	// warningDelayBonusCap caps the route-count bonus added to the
	// base grace window. See warningDelay.
	warningDelayBonusCap = 30 * time.Second
	// envWarningDelay overrides defaultWarningDelayBase with a Go duration
	// string (e.g. "90s", "2m"). Invalid or non-positive values are ignored.
	envWarningDelay = "NB_DNS_HEALTH_WARNING_DELAY"
)

// errNoUsableNameservers signals that a merged-domain group has no usable
// upstream servers. Callers should skip the group without treating it as a
// build failure.
var errNoUsableNameservers = errors.New("no usable nameservers")

// ReadyListener is a notification mechanism what indicate the server is ready to handle host dns address changes
type ReadyListener interface {
	OnReady()
}

// IosDnsManager is a dns manager interface for iOS
type IosDnsManager interface {
	ApplyDns(string)
}

// Server is a dns server interface
type Server interface {
	RegisterHandler(domains domain.List, handler dns.Handler, priority int)
	DeregisterHandler(domains domain.List, priority int)
	BeginBatch()
	EndBatch()
	CancelBatch()
	Initialize() error
	Stop()
	DnsIP() netip.Addr
	UpdateDNSServer(serial uint64, update nbdns.Config) error
	OnUpdatedHostDNSServer(addrs []netip.AddrPort)
	SearchDomains() []string
	UpdateServerConfig(domains dnsconfig.ServerDomains) error
	PopulateManagementDomain(mgmtURL *url.URL) error
	SetRouteSources(selected, active func() route.HAMap)
	SetFirewall(Firewall)
}

type nsGroupsByDomain struct {
	domain string
	groups []*nbdns.NameServerGroup
}

// nsGroupID identifies a nameserver group by the tuple (server list, domain
// list) so config updates produce stable IDs across recomputations.
type nsGroupID string

// nsHealthSnapshot is the input to projectNSGroupHealth, captured under
// s.mux so projection runs lock-free.
type nsHealthSnapshot struct {
	groups   []*nbdns.NameServerGroup
	merged   map[netip.AddrPort]UpstreamHealth
	selected route.HAMap
	active   route.HAMap
}

// nsGroupProj holds per-group state for the emission rules.
type nsGroupProj struct {
	// unhealthySince is the start of the current Unhealthy streak,
	// zero when the group is not currently Unhealthy.
	unhealthySince time.Time
	// everHealthy is sticky: once the group has been Healthy at least
	// once this session, subsequent failures skip warningDelay.
	everHealthy bool
	// warningActive tracks whether we've already published a warning
	// for the current streak, so recovery emits iff a warning did.
	warningActive bool
}

// nsGroupVerdict is the outcome of evaluateNSGroupHealth.
type nsGroupVerdict int

const (
	// nsVerdictUndecided means no upstream has a fresh observation
	// (startup before first query, or records aged past healthLookback).
	nsVerdictUndecided nsGroupVerdict = iota
	// nsVerdictHealthy means at least one upstream's most-recent
	// in-lookback observation is a success.
	nsVerdictHealthy
	// nsVerdictUnhealthy means at least one upstream has a recent
	// failure and none has a fresher success.
	nsVerdictUnhealthy
)

// DefaultServer dns server object
type DefaultServer struct {
	ctx        context.Context
	ctxCancel  context.CancelFunc
	shutdownWg sync.WaitGroup
	// disableSys disables system DNS management (e.g., /etc/resolv.conf updates) while keeping the DNS service running.
	// This is different from ServiceEnable=false from management which completely disables the DNS service.
	disableSys         bool
	mux                sync.Mutex
	service            service
	dnsMuxHandlers     []handlerWrapper
	localResolver      *local.Resolver
	wgInterface        WGIface
	hostManager        hostManager
	updateSerial       uint64
	previousConfigHash uint64
	currentConfig      HostDNSConfig
	currentConfigHash  uint64
	handlerChain       *HandlerChain
	extraDomains       map[domain.Domain]int
	batchMode          bool

	mgmtCacheResolver *mgmt.Resolver

	// permanent related properties
	permanent      bool
	hostsDNSHolder *hostsDNSHolder

	// fallbackHandler is the upstream resolver currently registered at
	// PriorityFallback. Tracked so registerFallback can Stop() the previous
	// instance instead of leaking its context.
	fallbackHandler handlerWithStop

	// make sense on mobile only
	searchDomainNotifier *notifier
	iosDnsManager        IosDnsManager

	statusRecorder *peer.Status
	stateManager   *statemanager.Manager
	// selectedRoutes returns admin-enabled client routes.
	selectedRoutes func() route.HAMap
	// activeRoutes returns the subset whose peer is in StatusConnected.
	activeRoutes func() route.HAMap

	nsGroups        []*nbdns.NameServerGroup
	healthProjectMu sync.Mutex
	// nsGroupProj is the per-group state used by the emission rules.
	// Accessed only under healthProjectMu.
	nsGroupProj map[nsGroupID]*nsGroupProj
	// warningDelayBase is the base grace window for health projection.
	// Set at construction, mutated only by tests. Read by the
	// refresher goroutine so never change it while one is running.
	warningDelayBase time.Duration
	// healthRefresh is buffered=1; writers coalesce, senders never block.
	// See refreshHealth for the lock-order rationale.
	healthRefresh chan struct{}
}

type handlerWithStop interface {
	dns.Handler
	Stop()
	ID() types.HandlerID
}

type upstreamHealthReporter interface {
	UpstreamHealth() map[netip.AddrPort]UpstreamHealth
}

type handlerWrapper struct {
	domain   string
	handler  handlerWithStop
	priority int
}

// DefaultServerConfig holds configuration parameters for NewDefaultServer
type DefaultServerConfig struct {
	WgInterface    WGIface
	CustomAddress  string
	StatusRecorder *peer.Status
	StateManager   *statemanager.Manager
	DisableSys     bool
}

// NewDefaultServer returns a new dns server
func NewDefaultServer(ctx context.Context, config DefaultServerConfig) (*DefaultServer, error) {
	var addrPort *netip.AddrPort
	if config.CustomAddress != "" {
		parsedAddrPort, err := netip.ParseAddrPort(config.CustomAddress)
		if err != nil {
			return nil, fmt.Errorf("unable to parse the custom dns address, got error: %s", err)
		}
		addrPort = &parsedAddrPort
	}

	var dnsService service
	if config.WgInterface.IsUserspaceBind() {
		dnsService = NewServiceViaMemory(config.WgInterface)
	} else {
		dnsService = newServiceViaListener(config.WgInterface, addrPort, nil)
	}

	server := newDefaultServer(ctx, config.WgInterface, dnsService, config.StatusRecorder, config.StateManager, config.DisableSys)
	return server, nil
}

// NewDefaultServerPermanentUpstream returns a new dns server. It optimized for mobile systems
func NewDefaultServerPermanentUpstream(
	ctx context.Context,
	wgInterface WGIface,
	hostsDnsList []netip.AddrPort,
	config nbdns.Config,
	listener listener.NetworkChangeListener,
	statusRecorder *peer.Status,
	disableSys bool,
) *DefaultServer {
	log.Debugf("host dns address list is: %v", hostsDnsList)
	ds := newDefaultServer(ctx, wgInterface, NewServiceViaMemory(wgInterface), statusRecorder, nil, disableSys)

	ds.hostsDNSHolder.set(hostsDnsList)
	ds.permanent = true
	ds.currentConfig = dnsConfigToHostDNSConfig(config, ds.service.RuntimeIP(), ds.service.RuntimePort())
	ds.searchDomainNotifier = newNotifier(ds.SearchDomains())
	ds.searchDomainNotifier.setListener(listener)
	setServerDns(ds)
	return ds
}

// NewDefaultServerIos returns a new dns server. It optimized for ios.
func NewDefaultServerIos(
	ctx context.Context,
	wgInterface WGIface,
	iosDnsManager IosDnsManager,
	statusRecorder *peer.Status,
	disableSys bool,
) *DefaultServer {
	ds := newDefaultServer(ctx, wgInterface, NewServiceViaMemory(wgInterface), statusRecorder, nil, disableSys)
	ds.iosDnsManager = iosDnsManager
	ds.permanent = true
	return ds
}

func newDefaultServer(
	ctx context.Context,
	wgInterface WGIface,
	dnsService service,
	statusRecorder *peer.Status,
	stateManager *statemanager.Manager,
	disableSys bool,
) *DefaultServer {
	handlerChain := NewHandlerChain()
	ctx, stop := context.WithCancel(ctx)

	mgmtCacheResolver := mgmt.NewResolver()
	mgmtCacheResolver.SetChainResolver(handlerChain, PriorityUpstream)

	defaultServer := &DefaultServer{
		ctx:               ctx,
		ctxCancel:         stop,
		disableSys:        disableSys,
		service:           dnsService,
		handlerChain:      handlerChain,
		extraDomains:      make(map[domain.Domain]int),
		localResolver:     local.NewResolver(),
		wgInterface:       wgInterface,
		statusRecorder:    statusRecorder,
		stateManager:      stateManager,
		hostsDNSHolder:    newHostsDNSHolder(),
		hostManager:       &noopHostConfigurator{},
		mgmtCacheResolver: mgmtCacheResolver,
		currentConfigHash: ^uint64(0), // Initialize to max uint64 to ensure first config is always applied
		warningDelayBase:  warningDelayBaseFromEnv(),
		healthRefresh:     make(chan struct{}, 1),
	}
	// Wire the local resolver against the peer status recorder so it can
	// suppress A/AAAA answers that point at disconnected peers (typical
	// case: synthesised private-service records pointing at an embedded
	// proxy peer that just went offline).
	defaultServer.localResolver.SetPeerConnectivity(localPeerConnectivity{statusRecorder})

	// register with root zone, handler chain takes care of the routing
	dnsService.RegisterMux(".", handlerChain)

	return defaultServer
}

// SetRouteSources wires the route-manager accessors used by health
// projection to classify each upstream for emission timing.
func (s *DefaultServer) SetRouteSources(selected, active func() route.HAMap) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.selectedRoutes = selected
	s.activeRoutes = active

	// Permanent / iOS constructors build the root handler before the
	// engine wires route sources, so its selectedRoutes callback would
	// otherwise remain nil and overlay upstreams would be classified
	// as public. Propagate the new accessors to existing handlers.
	type routeSettable interface {
		setSelectedRoutes(func() route.HAMap)
	}
	for _, entry := range s.dnsMuxHandlers {
		if h, ok := entry.handler.(routeSettable); ok {
			h.setSelectedRoutes(selected)
		}
	}
}

// RegisterHandler registers a handler for the given domains with the given priority.
// Any previously registered handler for the same domain and priority will be replaced.
func (s *DefaultServer) RegisterHandler(domains domain.List, handler dns.Handler, priority int) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.registerHandler(domains.ToPunycodeList(), handler, priority)

	// TODO: This will take over zones for non-wildcard domains, for which we might not have a handler in the chain
	for _, domain := range domains {
		s.extraDomains[toZone(domain)]++
	}
	if !s.batchMode {
		s.applyHostConfig()
	}
}

func (s *DefaultServer) registerHandler(domains []string, handler dns.Handler, priority int) {
	log.Debugf("registering handler %s with priority %d for %v", handler, priority, domains)

	for _, domain := range domains {
		if domain == "" {
			log.Warn("skipping empty domain")
			continue
		}

		s.handlerChain.AddHandler(domain, handler, priority)
	}
}

// DeregisterHandler deregisters the handler for the given domains with the given priority.
func (s *DefaultServer) DeregisterHandler(domains domain.List, priority int) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.deregisterHandler(domains.ToPunycodeList(), priority)
	for _, domain := range domains {
		zone := toZone(domain)
		s.extraDomains[zone]--
		if s.extraDomains[zone] <= 0 {
			delete(s.extraDomains, zone)
		}
	}
	if !s.batchMode {
		s.applyHostConfig()
	}
}

// BeginBatch starts batch mode for DNS handler registration/deregistration.
// In batch mode, applyHostConfig() is not called after each handler operation,
// allowing multiple handlers to be registered/deregistered efficiently.
// Must be followed by EndBatch() to apply the accumulated changes.
func (s *DefaultServer) BeginBatch() {
	s.mux.Lock()
	defer s.mux.Unlock()
	log.Debugf("DNS batch mode enabled")
	s.batchMode = true
}

// EndBatch ends batch mode and applies all accumulated DNS configuration changes.
func (s *DefaultServer) EndBatch() {
	s.mux.Lock()
	defer s.mux.Unlock()
	log.Debugf("DNS batch mode disabled, applying accumulated changes")
	s.batchMode = false
	s.applyHostConfig()
}

// CancelBatch cancels batch mode without applying accumulated changes.
// This is useful when operations fail partway through and you want to
// discard partial state rather than applying it.
func (s *DefaultServer) CancelBatch() {
	s.mux.Lock()
	defer s.mux.Unlock()
	log.Debugf("DNS batch mode cancelled, discarding accumulated changes")
	s.batchMode = false
}

func (s *DefaultServer) deregisterHandler(domains []string, priority int) {
	log.Debugf("deregistering handler with priority %d for %v", priority, domains)

	for _, domain := range domains {
		if domain == "" {
			log.Warn("skipping empty domain")
			continue
		}

		s.handlerChain.RemoveHandler(domain, priority)
	}
}

// Initialize instantiate host manager and the dns service
func (s *DefaultServer) Initialize() (err error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if !s.isUsingNoopHostManager() {
		// already initialized
		return nil
	}

	if s.permanent {
		err = s.service.Listen()
		if err != nil {
			return fmt.Errorf("service listen: %w", err)
		}
	}

	s.stateManager.RegisterState(&ShutdownState{})

	s.startHealthRefresher()

	// Keep using noop host manager if dns off requested or running in netstack mode.
	// Netstack mode currently doesn't have a way to receive DNS requests.
	// TODO: Use listener on localhost in netstack mode when running as root.
	if s.disableSys || netstack.IsEnabled() {
		log.Info("system DNS is disabled, not setting up host manager")
		return nil
	}

	hostManager, err := s.initialize()
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	s.hostManager = hostManager
	// On mobile-permanent setups the seeded host DNS list is the only
	// source until the first network-map arrives; register it now so DNS
	// works in that window. Desktop host managers register fallback when
	// applyConfiguration runs.
	if s.permanent {
		s.registerFallback()
	}
	return nil
}

// DnsIP returns the DNS resolver server IP address
//
// When kernel space interface used it return real DNS server listener IP address
// For bind interface, fake DNS resolver address returned (second last IP address from Nebird network)
func (s *DefaultServer) DnsIP() netip.Addr {
	return s.service.RuntimeIP()
}

// SetFirewall sets the firewall used for DNS port DNAT rules.
// This must be called before Initialize when using the listener-based service,
// because the firewall is typically not available at construction time.
func (s *DefaultServer) SetFirewall(fw Firewall) {
	if svc, ok := s.service.(*serviceViaListener); ok {
		svc.listenerFlagLock.Lock()
		svc.firewall = fw
		svc.listenerFlagLock.Unlock()
	}
}

// Stop stops the server
func (s *DefaultServer) Stop() {
	s.ctxCancel()
	s.shutdownWg.Wait()

	s.mux.Lock()
	defer s.mux.Unlock()

	if err := s.disableDNS(); err != nil {
		log.Errorf("failed to disable DNS: %v", err)
	}

	clear(s.extraDomains)

	// Clear health projection state so a subsequent Start doesn't
	// inherit sticky flags (notably everHealthy) that would bypass
	// the grace window during the next peer handshake.
	s.healthProjectMu.Lock()
	s.nsGroupProj = nil
	s.healthProjectMu.Unlock()
}

func (s *DefaultServer) disableDNS() (retErr error) {
	defer func() {
		if err := s.service.Stop(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("stop DNS service: %w", err))
		}
	}()

	if s.isUsingNoopHostManager() {
		return nil
	}

	if s.fallbackHandler != nil {
		log.Debugf("deregistering fallback handlers")
		s.clearFallback()
	}

	if err := s.hostManager.restoreHostDNS(); err != nil {
		log.Errorf("failed to restore host DNS settings: %v", err)
	} else if err := s.stateManager.DeleteState(&ShutdownState{}); err != nil {
		log.Errorf("failed to delete shutdown dns state: %v", err)
	}

	s.hostManager = &noopHostConfigurator{}

	return nil
}

// OnUpdatedHostDNSServer updates the fallback DNS upstreams. Called by Android
// outside the engine's sync mux when the OS reports a network change, so it
// takes s.mux to serialize against host manager swaps in Initialize/enableDNS.
func (s *DefaultServer) OnUpdatedHostDNSServer(hostsDnsList []netip.AddrPort) {
	s.hostsDNSHolder.set(hostsDnsList)
	log.Debugf("update host DNS settings: %+v", hostsDnsList)

	s.mux.Lock()
	defer s.mux.Unlock()
	s.registerFallback()
}

// UpdateDNSServer processes an update received from the management service
func (s *DefaultServer) UpdateDNSServer(serial uint64, update nbdns.Config) error {
	if s.ctx.Err() != nil {
		log.Infof("not updating DNS server as context is closed")
		return s.ctx.Err()
	}

	if serial < s.updateSerial {
		return fmt.Errorf("not applying dns update, error: "+
			"network update is %d behind the last applied update", s.updateSerial-serial)
	}

	s.mux.Lock()
	defer s.mux.Unlock()

	hash, err := hashstructure.Hash(update, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
		SlicesAsSets:    true,
		UseStringer:     true,
	})
	if err != nil {
		log.Errorf("unable to hash the dns configuration update, got error: %s", err)
	}

	if s.previousConfigHash == hash {
		log.Debugf("not applying the dns configuration update as there is nothing new")
		s.updateSerial = serial
		return nil
	}

	if err := s.applyConfiguration(update); err != nil {
		return fmt.Errorf("apply configuration: %w", err)
	}

	s.updateSerial = serial
	s.previousConfigHash = hash

	return nil
}

func (s *DefaultServer) SearchDomains() []string {
	var searchDomains []string

	for _, dConf := range s.currentConfig.Domains {
		if dConf.Disabled {
			continue
		}
		if dConf.MatchOnly {
			continue
		}
		searchDomains = append(searchDomains, dConf.Domain)
	}
	return searchDomains
}

func (s *DefaultServer) UpdateServerConfig(domains dnsconfig.ServerDomains) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.mgmtCacheResolver != nil {
		removedDomains, err := s.mgmtCacheResolver.UpdateFromServerDomains(s.ctx, domains)
		if err != nil {
			return fmt.Errorf("update management cache resolver: %w", err)
		}

		if len(removedDomains) > 0 {
			s.deregisterHandler(removedDomains.ToPunycodeList(), PriorityMgmtCache)
		}

		newDomains := s.mgmtCacheResolver.GetCachedDomains()
		if len(newDomains) > 0 {
			s.registerHandler(newDomains.ToPunycodeList(), s.mgmtCacheResolver, PriorityMgmtCache)
		}
	}

	return nil
}

func (s *DefaultServer) applyConfiguration(update nbdns.Config) error {
	// is the service should be Disabled, we stop the listener or fake resolver
	if update.ServiceEnable {
		if err := s.enableDNS(); err != nil {
			log.Errorf("failed to enable DNS: %v", err)
		}
	} else if !s.permanent {
		if err := s.disableDNS(); err != nil {
			log.Errorf("failed to disable DNS: %v", err)
		}
	}

	localMuxUpdates, localZones, err := s.buildLocalHandlerUpdate(update.CustomZones)
	if err != nil {
		return fmt.Errorf("local handler updater: %w", err)
	}

	upstreamMuxUpdates, err := s.buildUpstreamHandlerUpdate(update.NameServerGroups)
	if err != nil {
		return fmt.Errorf("upstream handler updater: %w", err)
	}
	muxUpdates := append(localMuxUpdates, upstreamMuxUpdates...) //nolint:gocritic

	s.updateMux(muxUpdates)

	s.localResolver.Update(localZones)

	s.currentConfig = dnsConfigToHostDNSConfig(update, s.service.RuntimeIP(), s.service.RuntimePort())

	if s.service.RuntimePort() != DefaultPort && !s.hostManager.supportCustomPort() {
		log.Warnf("the DNS manager of this peer doesn't support custom port. Disabling primary DNS setup. " +
			"Learn more at: https://docs.netbird.io/how-to/manage-dns-in-your-network#local-resolver")
		s.currentConfig.RouteAll = false
	}

	// Always apply host config for management updates, regardless of batch mode
	s.applyHostConfig()

	s.shutdownWg.Add(1)
	go func() {
		defer s.shutdownWg.Done()
		if err := s.stateManager.PersistState(s.ctx); err != nil {
			log.Errorf("Failed to persist dns state: %v", err)
		}
	}()

	if s.searchDomainNotifier != nil {
		s.searchDomainNotifier.onNewSearchDomains(s.SearchDomains())
	}

	s.updateNSGroupStates(update.NameServerGroups)

	return nil
}

func (s *DefaultServer) isUsingNoopHostManager() bool {
	_, isNoop := s.hostManager.(*noopHostConfigurator)
	return isNoop
}

func (s *DefaultServer) enableDNS() error {
	if err := s.service.Listen(); err != nil {
		return fmt.Errorf("start DNS service: %w", err)
	}

	if !s.isUsingNoopHostManager() {
		return nil
	}

	if s.disableSys || netstack.IsEnabled() {
		return nil
	}

	log.Info("DNS service re-enabled, initializing host manager")

	if !s.service.RuntimeIP().IsValid() {
		return errors.New("DNS service runtime IP is invalid")
	}

	hostManager, err := s.initialize()
	if err != nil {
		return fmt.Errorf("initialize host manager: %w", err)
	}
	s.hostManager = hostManager

	return nil
}

func (s *DefaultServer) applyHostConfig() {
	// prevent reapplying config if we're shutting down
	if s.ctx.Err() != nil {
		return
	}

	config := s.currentConfig

	existingDomains := make(map[string]struct{})
	for _, d := range config.Domains {
		existingDomains[d.Domain] = struct{}{}
	}

	// add extra domains only if they're not already in the config
	for domain := range s.extraDomains {
		domainStr := domain.PunycodeString()

		if _, exists := existingDomains[domainStr]; !exists {
			config.Domains = append(config.Domains, DomainConfig{
				Domain:    domainStr,
				MatchOnly: true,
			})
		}
	}

	log.Debugf("extra match domains: %v", maps.Keys(s.extraDomains))

	hash, err := hashstructure.Hash(config, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
		SlicesAsSets:    true,
		UseStringer:     true,
	})
	if err != nil {
		log.Warnf("unable to hash the host dns configuration, will apply config anyway: %s", err)
		// Fall through to apply config anyway (fail-safe approach)
	} else if s.currentConfigHash == hash {
		log.Debugf("not applying host config as there are no changes")
		return
	}

	log.Debugf("applying host config as there are changes")
	if err := s.hostManager.applyDNSConfig(config, s.stateManager); err != nil {
		log.Errorf("failed to apply DNS host manager update: %v", err)
		return
	}

	// Only update hash if it was computed successfully and config was applied
	if err == nil {
		s.currentConfigHash = hash
	}

	s.registerFallback()
}

// registerFallback registers original nameservers as low-priority fallback handlers.
// Replaces and Stop()s the previously-registered fallback handler so its
// context is released rather than leaked until GC.
func (s *DefaultServer) registerFallback() {
	originalNameservers := s.hostManager.getOriginalNameservers()

	serverIP := s.service.RuntimeIP()
	var servers []netip.AddrPort
	for _, ns := range originalNameservers {
		if ns == serverIP {
			log.Debugf("skipping original nameserver %s as it is the same as the server IP %s", ns, serverIP)
			continue
		}
		servers = append(servers, netip.AddrPortFrom(ns, DefaultPort))
	}

	if len(servers) == 0 {
		log.Debugf("no fallback upstreams to register; clearing PriorityFallback handler")
		s.clearFallback()
		return
	}

	log.Infof("registering original nameservers %v as upstream handlers with priority %d", servers, PriorityFallback)

	handler, err := newUpstreamResolver(
		s.ctx,
		s.wgInterface,
		s.statusRecorder,
		s.hostsDNSHolder,
		nbdns.RootZone,
	)
	if err != nil {
		log.Errorf("failed to create upstream resolver for original nameservers: %v", err)
		return
	}
	handler.selectedRoutes = s.selectedRoutes
	handler.addRace(servers)

	prev := s.fallbackHandler
	s.fallbackHandler = handler
	s.registerHandler([]string{nbdns.RootZone}, handler, PriorityFallback)
	if prev != nil {
		prev.Stop()
	}
}

func (s *DefaultServer) clearFallback() {
	s.deregisterHandler([]string{nbdns.RootZone}, PriorityFallback)
	if s.fallbackHandler != nil {
		s.fallbackHandler.Stop()
		s.fallbackHandler = nil
	}
}

func (s *DefaultServer) buildLocalHandlerUpdate(customZones []nbdns.CustomZone) ([]handlerWrapper, []nbdns.CustomZone, error) {
	var muxUpdates []handlerWrapper
	var zones []nbdns.CustomZone

	for _, customZone := range customZones {
		if len(customZone.Records) == 0 {
			log.Warnf("received a custom zone with empty records, skipping domain: %s", customZone.Domain)
			continue
		}

		muxUpdates = append(muxUpdates, handlerWrapper{
			domain:   customZone.Domain,
			handler:  s.localResolver,
			priority: PriorityLocal,
		})

		// zone records contain the fqdn, so we can just flatten them
		var localRecords []nbdns.SimpleRecord
		for _, record := range customZone.Records {
			if record.Class != nbdns.DefaultClass {
				log.Warnf("received an invalid class type: %s", record.Class)
				continue
			}
			localRecords = append(localRecords, record)
		}
		customZone.Records = localRecords
		zones = append(zones, customZone)
	}

	return muxUpdates, zones, nil
}

func (s *DefaultServer) buildUpstreamHandlerUpdate(nameServerGroups []*nbdns.NameServerGroup) ([]handlerWrapper, error) {
	var muxUpdates []handlerWrapper

	for _, nsGroup := range nameServerGroups {
		if len(nsGroup.NameServers) == 0 {
			log.Warn("received a nameserver group with empty nameserver list")
			continue
		}

		if !nsGroup.Primary && len(nsGroup.Domains) == 0 {
			return nil, fmt.Errorf("received a non primary nameserver group with an empty domain list")
		}

		for _, domain := range nsGroup.Domains {
			if domain == "" {
				return nil, fmt.Errorf("received a nameserver group with an empty domain element")
			}
		}
	}

	groupedNS := groupNSGroupsByDomain(nameServerGroups)

	for _, domainGroup := range groupedNS {
		priority := PriorityUpstream
		if domainGroup.domain == nbdns.RootZone {
			priority = PriorityDefault
		}

		update, err := s.buildMergedDomainHandler(domainGroup, priority)
		if err != nil {
			if errors.Is(err, errNoUsableNameservers) {
				log.Errorf("no usable nameservers for domain=%s", domainGroup.domain)
				continue
			}
			return nil, err
		}
		muxUpdates = append(muxUpdates, *update)
	}

	return muxUpdates, nil
}

// buildMergedDomainHandler merges every nameserver group that targets the
// same domain into one handler whose inner groups are raced in parallel.
func (s *DefaultServer) buildMergedDomainHandler(domainGroup nsGroupsByDomain, priority int) (*handlerWrapper, error) {
	handler, err := newUpstreamResolver(
		s.ctx,
		s.wgInterface,
		s.statusRecorder,
		s.hostsDNSHolder,
		domain.Domain(domainGroup.domain),
	)
	if err != nil {
		return nil, fmt.Errorf("create upstream resolver: %v", err)
	}
	handler.selectedRoutes = s.selectedRoutes

	for _, nsGroup := range domainGroup.groups {
		servers := s.filterNameServers(nsGroup.NameServers)
		if len(servers) == 0 {
			log.Warnf("nameserver group for domain=%s yielded no usable servers, skipping", domainGroup.domain)
			continue
		}
		handler.addRace(servers)
	}

	if len(handler.upstreamServers) == 0 {
		handler.Stop()
		return nil, errNoUsableNameservers
	}

	log.Debugf("creating merged handler for domain=%s with %d group(s) priority=%d", domainGroup.domain, len(handler.upstreamServers), priority)

	return &handlerWrapper{
		domain:   domainGroup.domain,
		handler:  handler,
		priority: priority,
	}, nil
}

func (s *DefaultServer) filterNameServers(nameServers []nbdns.NameServer) []netip.AddrPort {
	var out []netip.AddrPort
	for _, ns := range nameServers {
		if ns.NSType != nbdns.UDPNameServerType {
			log.Warnf("skipping nameserver %s with type %s, this peer supports only %s",
				ns.IP.String(), ns.NSType.String(), nbdns.UDPNameServerType.String())
			continue
		}
		if ns.IP == s.service.RuntimeIP() {
			log.Warnf("skipping nameserver %s as it matches our DNS server IP, preventing potential loop", ns.IP)
			continue
		}
		out = append(out, ns.AddrPort())
	}
	return out
}

// usableNameServers returns the subset of nameServers the handler would
// actually query. Matches filterNameServers without the warning logs, so
// it's safe to call on every health-projection tick.
func (s *DefaultServer) usableNameServers(nameServers []nbdns.NameServer) []netip.AddrPort {
	var runtimeIP netip.Addr
	if s.service != nil {
		runtimeIP = s.service.RuntimeIP()
	}
	var out []netip.AddrPort
	for _, ns := range nameServers {
		if ns.NSType != nbdns.UDPNameServerType {
			continue
		}
		if runtimeIP.IsValid() && ns.IP == runtimeIP {
			continue
		}
		out = append(out, ns.AddrPort())
	}
	return out
}

func (s *DefaultServer) updateMux(muxUpdates []handlerWrapper) {
	// this will introduce a short period of time when the server is not able to handle DNS requests
	for _, existing := range s.dnsMuxHandlers {
		s.deregisterHandler([]string{existing.domain}, existing.priority)
		// The local resolver is a persistent singleton shared by every custom
		// zone and reused across config updates. Its chain registrations are
		// per-config and must be deregistered, but Stop() cancels its lookup
		// context (breaking external CNAME-target resolution) and clears its
		// records, so it must not be torn down here.
		if existing.handler != s.localResolver {
			existing.handler.Stop()
		}
	}

	for _, update := range muxUpdates {
		s.registerHandler([]string{update.domain}, update.handler, update.priority)
	}

	s.dnsMuxHandlers = muxUpdates
}

// updateNSGroupStates records the new group set and pokes the refresher.
// Must hold s.mux; projection runs async (see refreshHealth for why).
func (s *DefaultServer) updateNSGroupStates(groups []*nbdns.NameServerGroup) {
	s.nsGroups = groups
	select {
	case s.healthRefresh <- struct{}{}:
	default:
	}
}

// refreshHealth runs one projection cycle. Must not be called while
// holding s.mux: the route callbacks re-enter routemanager's lock.
func (s *DefaultServer) refreshHealth() {
	s.mux.Lock()
	groups := s.nsGroups
	merged := s.collectUpstreamHealth()
	selFn := s.selectedRoutes
	actFn := s.activeRoutes
	s.mux.Unlock()

	var selected, active route.HAMap
	if selFn != nil {
		selected = selFn()
	}
	if actFn != nil {
		active = actFn()
	}

	s.projectNSGroupHealth(nsHealthSnapshot{
		groups:   groups,
		merged:   merged,
		selected: selected,
		active:   active,
	})
}

// projectNSGroupHealth applies the emission rules to the snapshot and
// publishes the resulting NSGroupStates. Serialized by healthProjectMu,
// lock-free wrt s.mux.
//
// Rules:
//   - Healthy: emit recovery iff warningActive; set everHealthy.
//   - Unhealthy: stamp unhealthySince on streak start; emit warning
//     iff any of immediate / everHealthy / elapsed >= effective delay.
//   - Undecided: no-op.
//
// "Immediate" means the group has at least one upstream that's public
// or overlay+Connected: no peer-startup race to wait out.
func (s *DefaultServer) projectNSGroupHealth(snap nsHealthSnapshot) {
	if s.statusRecorder == nil {
		return
	}

	s.healthProjectMu.Lock()
	defer s.healthProjectMu.Unlock()

	if s.nsGroupProj == nil {
		s.nsGroupProj = make(map[nsGroupID]*nsGroupProj)
	}

	now := time.Now()
	delay := s.warningDelay(haMapRouteCount(snap.selected))
	states := make([]peer.NSGroupState, 0, len(snap.groups))
	seen := make(map[nsGroupID]struct{}, len(snap.groups))
	for _, group := range snap.groups {
		servers := s.usableNameServers(group.NameServers)
		if len(servers) == 0 {
			continue
		}
		verdict, groupErr := evaluateNSGroupHealth(snap.merged, servers, now)
		id := generateGroupKey(group)
		seen[id] = struct{}{}

		immediate := s.groupHasImmediateUpstream(servers, snap)

		p, known := s.nsGroupProj[id]
		if !known {
			p = &nsGroupProj{}
			s.nsGroupProj[id] = p
		}

		enabled := true
		switch verdict {
		case nsVerdictHealthy:
			enabled = s.projectHealthy(p, servers)
		case nsVerdictUnhealthy:
			enabled = s.projectUnhealthy(p, servers, immediate, now, delay)
		case nsVerdictUndecided:
			// Stay Available until evidence says otherwise, unless a
			// warning is already active for this group. Also clear any
			// prior Unhealthy streak so a later Unhealthy verdict starts
			// a fresh grace window rather than inheriting a stale one.
			p.unhealthySince = time.Time{}
			enabled = !p.warningActive
			groupErr = nil
		}

		states = append(states, peer.NSGroupState{
			ID:      string(id),
			Servers: servers,
			Domains: group.Domains,
			Enabled: enabled,
			Error:   groupErr,
		})
	}
	for id := range s.nsGroupProj {
		if _, ok := seen[id]; !ok {
			delete(s.nsGroupProj, id)
		}
	}
	s.statusRecorder.UpdateDNSStates(states)
}

// projectHealthy records a healthy tick on p and publishes a recovery
// event iff a warning was active for the current streak. Returns the
// Enabled flag to record in NSGroupState.
func (s *DefaultServer) projectHealthy(p *nsGroupProj, servers []netip.AddrPort) bool {
	p.everHealthy = true
	wasUnhealthy := !p.unhealthySince.IsZero() || p.warningActive
	p.unhealthySince = time.Time{}
	if wasUnhealthy {
		s.flushHostDNSCache()
	}
	if !p.warningActive {
		return true
	}
	log.Debugf("DNS health: group [%s] recovered, emitting event", joinAddrPorts(servers))
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_DNS,
		"Nameserver group recovered",
		"DNS servers are reachable again.",
		map[string]string{"upstreams": joinAddrPorts(servers)},
	)
	p.warningActive = false
	return true
}

// flushHostDNSCache asks the host manager to drop the OS-level DNS cache,
// when the platform supports it (currently macOS). While the overlay
// upstreams for a match domain are unreachable (e.g. right after wake from
// sleep, before tunnels re-establish), queries can be answered by the
// public resolvers and the OS caches those answers for their full TTL.
// Flushing on the unhealthy->healthy transition makes clients pick up the
// overlay answers again immediately instead of serving stale public ones.
func (s *DefaultServer) flushHostDNSCache() {
	flusher, ok := s.hostManager.(interface{ flushDNSCache() error })
	if !ok {
		return
	}
	go func() {
		if err := flusher.flushDNSCache(); err != nil {
			log.Warnf("failed to flush host DNS cache after upstream recovery: %v", err)
		}
	}()
}

// projectUnhealthy records an unhealthy tick on p, publishes the
// warning when the emission rules fire, and returns the Enabled flag
// to record in NSGroupState.
func (s *DefaultServer) projectUnhealthy(p *nsGroupProj, servers []netip.AddrPort, immediate bool, now time.Time, delay time.Duration) bool {
	streakStart := p.unhealthySince.IsZero()
	if streakStart {
		p.unhealthySince = now
	}
	reason := unhealthyEmitReason(immediate, p.everHealthy, now.Sub(p.unhealthySince), delay)
	switch {
	case reason != "" && !p.warningActive:
		log.Debugf("DNS health: group [%s] unreachable, emitting event (reason=%s)", joinAddrPorts(servers), reason)
		s.statusRecorder.PublishEvent(
			proto.SystemEvent_WARNING,
			proto.SystemEvent_DNS,
			"Nameserver group unreachable",
			"Unable to reach one or more DNS servers. This might affect your ability to connect to some services.",
			map[string]string{"upstreams": joinAddrPorts(servers)},
		)
		p.warningActive = true
	case streakStart && reason == "":
		// One line per streak, not per tick.
		log.Debugf("DNS health: group [%s] unreachable but holding warning for up to %v (overlay-routed, no connected peer)", joinAddrPorts(servers), delay)
	}
	return false
}

// warningDelayBaseFromEnv returns the base grace window, honoring
// envWarningDelay when it holds a valid positive Go duration. Invalid or
// non-positive values fall back to defaultWarningDelayBase.
func warningDelayBaseFromEnv() time.Duration {
	val := os.Getenv(envWarningDelay)
	if val == "" {
		return defaultWarningDelayBase
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Warnf("invalid %s value %q, using default %v: %v", envWarningDelay, val, defaultWarningDelayBase, err)
		return defaultWarningDelayBase
	}
	if d <= 0 {
		log.Warnf("%s must be positive, got %v, using default %v", envWarningDelay, d, defaultWarningDelayBase)
		return defaultWarningDelayBase
	}
	return d
}

// warningDelay returns the grace window for the given selected-route
// count. Scales gently: +1s per 100 routes, capped by
// warningDelayBonusCap. Parallel handshakes mean handshake time grows
// much slower than route count, so linear scaling would overcorrect.
//
// TODO: revisit the scaling curve with real-world data — the current
// values are a reasonable starting point, not a measured fit.
func (s *DefaultServer) warningDelay(routeCount int) time.Duration {
	bonus := time.Duration(routeCount/100) * time.Second
	if bonus > warningDelayBonusCap {
		bonus = warningDelayBonusCap
	}
	return s.warningDelayBase + bonus
}

// groupHasImmediateUpstream reports whether the group has at least one
// upstream in a classification that bypasses the grace window: public
// (outside the overlay range and not routed), or overlay/routed with a
// Connected peer.
//
// TODO(ipv6): include the v6 overlay prefix once it's plumbed in.
func (s *DefaultServer) groupHasImmediateUpstream(servers []netip.AddrPort, snap nsHealthSnapshot) bool {
	var overlayV4 netip.Prefix
	if s.wgInterface != nil {
		overlayV4 = s.wgInterface.Address().Network
	}
	for _, srv := range servers {
		addr := srv.Addr().Unmap()
		overlay := overlayV4.IsValid() && overlayV4.Contains(addr)
		selMatched, selDynamic := haMapContains(snap.selected, addr)
		// Treat an unknown (dynamic selected route) as possibly routed:
		// the upstream might reach through a dynamic route whose Network
		// hasn't resolved yet, and classifying as public would bypass
		// the startup grace window.
		routed := selMatched || selDynamic
		if !overlay && !routed {
			return true
		}
		if actMatched, _ := haMapContains(snap.active, addr); actMatched {
			return true
		}
	}
	return false
}

// collectUpstreamHealth merges health snapshots across handlers, keeping
// the most recent success and failure per upstream when an address appears
// in more than one handler.
func (s *DefaultServer) collectUpstreamHealth() map[netip.AddrPort]UpstreamHealth {
	merged := make(map[netip.AddrPort]UpstreamHealth)
	for _, entry := range s.dnsMuxHandlers {
		reporter, ok := entry.handler.(upstreamHealthReporter)
		if !ok {
			continue
		}
		for addr, h := range reporter.UpstreamHealth() {
			existing, have := merged[addr]
			if !have {
				merged[addr] = h
				continue
			}
			if h.LastOk.After(existing.LastOk) {
				existing.LastOk = h.LastOk
			}
			if h.LastFail.After(existing.LastFail) {
				existing.LastFail = h.LastFail
				existing.LastErr = h.LastErr
			}
			merged[addr] = existing
		}
	}
	return merged
}

func (s *DefaultServer) startHealthRefresher() {
	s.shutdownWg.Add(1)
	go func() {
		defer s.shutdownWg.Done()
		ticker := time.NewTicker(nsGroupHealthRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
			case <-s.healthRefresh:
			}
			s.refreshHealth()
		}
	}()
}

// evaluateNSGroupHealth decides a group's verdict from query records
// alone. Per upstream, the most-recent-in-lookback observation wins.
// Group is Healthy if any upstream is fresh-working, Unhealthy if any
// is fresh-broken with no fresh-working sibling, Undecided otherwise.
func evaluateNSGroupHealth(merged map[netip.AddrPort]UpstreamHealth, servers []netip.AddrPort, now time.Time) (nsGroupVerdict, error) {
	anyWorking := false
	anyBroken := false
	var mostRecentFail time.Time
	var mostRecentErr string

	for _, srv := range servers {
		h, ok := merged[srv]
		if !ok {
			continue
		}
		switch classifyUpstreamHealth(h, now) {
		case upstreamFresh:
			anyWorking = true
		case upstreamBroken:
			anyBroken = true
			if h.LastFail.After(mostRecentFail) {
				mostRecentFail = h.LastFail
				mostRecentErr = h.LastErr
			}
		}
	}

	if anyWorking {
		return nsVerdictHealthy, nil
	}
	if anyBroken {
		if mostRecentErr == "" {
			return nsVerdictUnhealthy, nil
		}
		return nsVerdictUnhealthy, errors.New(mostRecentErr)
	}
	return nsVerdictUndecided, nil
}

// upstreamClassification is the per-upstream verdict within healthLookback.
type upstreamClassification int

const (
	upstreamStale upstreamClassification = iota
	upstreamFresh
	upstreamBroken
)

// classifyUpstreamHealth compares the last ok and last fail timestamps
// against healthLookback and returns which one (if any) counts. Fresh
// wins when both are in-window and ok is newer; broken otherwise.
func classifyUpstreamHealth(h UpstreamHealth, now time.Time) upstreamClassification {
	okRecent := !h.LastOk.IsZero() && now.Sub(h.LastOk) <= healthLookback
	failRecent := !h.LastFail.IsZero() && now.Sub(h.LastFail) <= healthLookback
	switch {
	case okRecent && failRecent:
		if h.LastOk.After(h.LastFail) {
			return upstreamFresh
		}
		return upstreamBroken
	case okRecent:
		return upstreamFresh
	case failRecent:
		return upstreamBroken
	}
	return upstreamStale
}

func joinAddrPorts(servers []netip.AddrPort) string {
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		parts = append(parts, s.String())
	}
	return strings.Join(parts, ", ")
}

// generateGroupKey returns a stable identity for an NS group so health
// state (everHealthy / warningActive) survives reorderings in the
// configured nameserver or domain lists.
func generateGroupKey(nsGroup *nbdns.NameServerGroup) nsGroupID {
	servers := make([]string, 0, len(nsGroup.NameServers))
	for _, ns := range nsGroup.NameServers {
		servers = append(servers, ns.AddrPort().String())
	}
	slices.Sort(servers)
	domains := slices.Clone(nsGroup.Domains)
	slices.Sort(domains)
	return nsGroupID(fmt.Sprintf("%v_%v", servers, domains))
}

// groupNSGroupsByDomain groups nameserver groups by their match domains
func groupNSGroupsByDomain(nsGroups []*nbdns.NameServerGroup) []nsGroupsByDomain {
	domainMap := make(map[string][]*nbdns.NameServerGroup)

	for _, group := range nsGroups {
		if group.Primary {
			domainMap[nbdns.RootZone] = append(domainMap[nbdns.RootZone], group)
			continue
		}

		for _, domain := range group.Domains {
			if domain == "" {
				continue
			}
			domainMap[domain] = append(domainMap[domain], group)
		}
	}

	var result []nsGroupsByDomain
	for domain, groups := range domainMap {
		result = append(result, nsGroupsByDomain{
			domain: domain,
			groups: groups,
		})
	}

	return result
}

func toZone(d domain.Domain) domain.Domain {
	return domain.Domain(
		nbdns.NormalizeZone(
			dns.Fqdn(
				strings.ToLower(d.PunycodeString()),
			),
		),
	)
}

// unhealthyEmitReason returns the tag of the rule that fires the
// warning now, or "" if the group is still inside its grace window.
func unhealthyEmitReason(immediate, everHealthy bool, elapsed, delay time.Duration) string {
	switch {
	case immediate:
		return "immediate"
	case everHealthy:
		return "ever-healthy"
	case elapsed >= delay:
		return "grace-elapsed"
	default:
		return ""
	}
}

// PopulateManagementDomain populates the DNS cache with management domain
func (s *DefaultServer) PopulateManagementDomain(mgmtURL *url.URL) error {
	if s.mgmtCacheResolver != nil {
		return s.mgmtCacheResolver.PopulateFromConfig(s.ctx, mgmtURL)
	}
	return nil
}

// localPeerConnectivity adapts *peer.Status to local.PeerConnectivity so
// the local resolver can ask "is this IP a known peer and is it
// connected?" without taking on the peer package as a dependency.
// A nil status recorder always reports known=false so the resolver
// short-circuits to the legacy "return everything" path.
type localPeerConnectivity struct {
	status *peer.Status
}

// IsConnectedByIP looks the IP up in the peerstore and surfaces both
// the known and connected bits. Used by Resolver.filterDisconnectedPeerAnswers.
func (l localPeerConnectivity) IsConnectedByIP(ip string) (known, connected bool) {
	if l.status == nil {
		return false, false
	}
	state, ok := l.status.PeerStateByIP(ip)
	if !ok {
		return false, false
	}
	return true, state.ConnStatus == peer.StatusConnected
}
