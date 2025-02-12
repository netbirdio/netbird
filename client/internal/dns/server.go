package dns

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sync"

	"github.com/miekg/dns"
	"github.com/mitchellh/hashstructure/v2"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbdns "github.com/netbirdio/netbird/dns"
)

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
	RegisterHandler(domains []string, handler dns.Handler, priority int)
	DeregisterHandler(domains []string, priority int)
	Initialize() error
	Stop()
	DnsIP() string
	UpdateDNSServer(serial uint64, update nbdns.Config) error
	OnUpdatedHostDNSServer(strings []string)
	SearchDomains() []string
	ProbeAvailability()
}

type handlerID string

type nsGroupsByDomain struct {
	domain string
	groups []*nbdns.NameServerGroup
}

// DefaultServer dns server object
type DefaultServer struct {
	ctx                context.Context
	ctxCancel          context.CancelFunc
	disableSys         bool
	mux                sync.Mutex
	service            service
	dnsMuxMap          registeredHandlerMap
	localResolver      *localResolver
	wgInterface        WGIface
	hostManager        hostManager
	updateSerial       uint64
	previousConfigHash uint64
	currentConfig      HostDNSConfig
	handlerChain       *HandlerChain

	// permanent related properties
	permanent      bool
	hostsDNSHolder *hostsDNSHolder

	// make sense on mobile only
	searchDomainNotifier *notifier
	iosDnsManager        IosDnsManager

	statusRecorder *peer.Status
	stateManager   *statemanager.Manager
}

type handlerWithStop interface {
	dns.Handler
	stop()
	probeAvailability()
	id() handlerID
}

type handlerWrapper struct {
	domain   string
	handler  handlerWithStop
	priority int
}

type registeredHandlerMap map[handlerID]handlerWrapper

// NewDefaultServer returns a new dns server
func NewDefaultServer(
	ctx context.Context,
	wgInterface WGIface,
	customAddress string,
	statusRecorder *peer.Status,
	stateManager *statemanager.Manager,
	disableSys bool,
) (*DefaultServer, error) {
	var addrPort *netip.AddrPort
	if customAddress != "" {
		parsedAddrPort, err := netip.ParseAddrPort(customAddress)
		if err != nil {
			return nil, fmt.Errorf("unable to parse the custom dns address, got error: %s", err)
		}
		addrPort = &parsedAddrPort
	}

	var dnsService service
	if wgInterface.IsUserspaceBind() {
		dnsService = NewServiceViaMemory(wgInterface)
	} else {
		dnsService = newServiceViaListener(wgInterface, addrPort)
	}

	return newDefaultServer(ctx, wgInterface, dnsService, statusRecorder, stateManager, disableSys), nil
}

// NewDefaultServerPermanentUpstream returns a new dns server. It optimized for mobile systems
func NewDefaultServerPermanentUpstream(
	ctx context.Context,
	wgInterface WGIface,
	hostsDnsList []string,
	config nbdns.Config,
	listener listener.NetworkChangeListener,
	statusRecorder *peer.Status,
	disableSys bool,
) *DefaultServer {
	log.Debugf("host dns address list is: %v", hostsDnsList)
	ds := newDefaultServer(ctx, wgInterface, NewServiceViaMemory(wgInterface), statusRecorder, nil, disableSys)
	ds.hostsDNSHolder.set(hostsDnsList)
	ds.permanent = true
	ds.addHostRootZone()
	ds.currentConfig = dnsConfigToHostDNSConfig(config, ds.service.RuntimeIP(), ds.service.RuntimePort())
	ds.searchDomainNotifier = newNotifier(ds.SearchDomains())
	ds.searchDomainNotifier.setListener(listener)
	setServerDns(ds)
	return ds
}

// NewDefaultServerIos returns a new dns server. It optimized for ios
func NewDefaultServerIos(
	ctx context.Context,
	wgInterface WGIface,
	iosDnsManager IosDnsManager,
	statusRecorder *peer.Status,
	disableSys bool,
) *DefaultServer {
	ds := newDefaultServer(ctx, wgInterface, NewServiceViaMemory(wgInterface), statusRecorder, nil, disableSys)
	ds.iosDnsManager = iosDnsManager
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
	ctx, stop := context.WithCancel(ctx)
	defaultServer := &DefaultServer{
		ctx:          ctx,
		ctxCancel:    stop,
		disableSys:   disableSys,
		service:      dnsService,
		handlerChain: NewHandlerChain(),
		dnsMuxMap:    make(registeredHandlerMap),
		localResolver: &localResolver{
			registeredMap: make(registrationMap),
		},
		wgInterface:    wgInterface,
		statusRecorder: statusRecorder,
		stateManager:   stateManager,
		hostsDNSHolder: newHostsDNSHolder(),
	}

	return defaultServer
}

func (s *DefaultServer) RegisterHandler(domains []string, handler dns.Handler, priority int) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.registerHandler(domains, handler, priority)
}

func (s *DefaultServer) registerHandler(domains []string, handler dns.Handler, priority int) {
	log.Debugf("registering handler %s with priority %d", handler, priority)

	for _, domain := range domains {
		if domain == "" {
			log.Warn("skipping empty domain")
			continue
		}
		s.handlerChain.AddHandler(domain, handler, priority)
		s.service.RegisterMux(nbdns.NormalizeZone(domain), s.handlerChain)
	}
}

func (s *DefaultServer) DeregisterHandler(domains []string, priority int) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.deregisterHandler(domains, priority)
}

func (s *DefaultServer) deregisterHandler(domains []string, priority int) {
	log.Debugf("deregistering handler %v with priority %d", domains, priority)

	for _, domain := range domains {
		if domain == "" {
			log.Warn("skipping empty domain")
			continue
		}

		s.handlerChain.RemoveHandler(domain, priority)

		// Only deregister from service if no handlers remain
		if !s.handlerChain.HasHandlers(domain) {
			s.service.DeregisterMux(nbdns.NormalizeZone(domain))
		}
	}
}

// Initialize instantiate host manager and the dns service
func (s *DefaultServer) Initialize() (err error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.hostManager != nil {
		return nil
	}

	if s.permanent {
		err = s.service.Listen()
		if err != nil {
			return fmt.Errorf("service listen: %w", err)
		}
	}

	s.stateManager.RegisterState(&ShutdownState{})

	// use noop host manager if requested or running in netstack mode.
	// Netstack mode currently doesn't have a way to receive DNS requests.
	// TODO: Use listener on localhost in netstack mode when running as root.
	if s.disableSys || netstack.IsEnabled() {
		log.Info("system DNS is disabled, not setting up host manager")
		s.hostManager = &noopHostConfigurator{}
		return nil
	}

	s.hostManager, err = s.initialize()
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	return nil
}

// DnsIP returns the DNS resolver server IP address
//
// When kernel space interface used it return real DNS server listener IP address
// For bind interface, fake DNS resolver address returned (second last IP address from Nebird network)
func (s *DefaultServer) DnsIP() string {
	return s.service.RuntimeIP()
}

// Stop stops the server
func (s *DefaultServer) Stop() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.ctxCancel()

	if s.hostManager != nil {
		if err := s.hostManager.restoreHostDNS(); err != nil {
			log.Error("failed to restore host DNS settings: ", err)
		} else if err := s.stateManager.DeleteState(&ShutdownState{}); err != nil {
			log.Errorf("failed to delete shutdown dns state: %v", err)
		}
	}

	s.service.Stop()
}

// OnUpdatedHostDNSServer update the DNS servers addresses for root zones
// It will be applied if the mgm server do not enforce DNS settings for root zone

func (s *DefaultServer) OnUpdatedHostDNSServer(hostsDnsList []string) {
	s.hostsDNSHolder.set(hostsDnsList)

	// Check if there's any root handler
	var hasRootHandler bool
	for _, handler := range s.dnsMuxMap {
		if handler.domain == nbdns.RootZone {
			hasRootHandler = true
			break
		}
	}

	if hasRootHandler {
		log.Debugf("on new host DNS config but skip to apply it")
		return
	}

	log.Debugf("update host DNS settings: %+v", hostsDnsList)
	s.addHostRootZone()
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

	if s.hostManager == nil {
		return fmt.Errorf("dns service is not initialized yet")
	}

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

// ProbeAvailability tests each upstream group's servers for availability
// and deactivates the group if no server responds
func (s *DefaultServer) ProbeAvailability() {
	var wg sync.WaitGroup
	for _, mux := range s.dnsMuxMap {
		wg.Add(1)
		go func(mux handlerWithStop) {
			defer wg.Done()
			mux.probeAvailability()
		}(mux.handler)
	}
	wg.Wait()
}

func (s *DefaultServer) applyConfiguration(update nbdns.Config) error {
	// is the service should be Disabled, we stop the listener or fake resolver
	// and proceed with a regular update to clean up the handlers and records
	if update.ServiceEnable {
		_ = s.service.Listen()
	} else if !s.permanent {
		s.service.Stop()
	}

	localMuxUpdates, localRecords, err := s.buildLocalHandlerUpdate(update.CustomZones)
	if err != nil {
		return fmt.Errorf("not applying dns update, error: %v", err)
	}
	upstreamMuxUpdates, err := s.buildUpstreamHandlerUpdate(update.NameServerGroups)
	if err != nil {
		return fmt.Errorf("not applying dns update, error: %v", err)
	}
	muxUpdates := append(localMuxUpdates, upstreamMuxUpdates...) //nolint:gocritic

	s.updateMux(muxUpdates)
	s.updateLocalResolver(localRecords)
	s.currentConfig = dnsConfigToHostDNSConfig(update, s.service.RuntimeIP(), s.service.RuntimePort())

	hostUpdate := s.currentConfig
	if s.service.RuntimePort() != defaultPort && !s.hostManager.supportCustomPort() {
		log.Warnf("the DNS manager of this peer doesn't support custom port. Disabling primary DNS setup. " +
			"Learn more at: https://docs.netbird.io/how-to/manage-dns-in-your-network#local-resolver")
		hostUpdate.RouteAll = false
	}

	if err = s.hostManager.applyDNSConfig(hostUpdate, s.stateManager); err != nil {
		log.Error(err)
	}

	go func() {
		// persist dns state right away
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

func (s *DefaultServer) buildLocalHandlerUpdate(customZones []nbdns.CustomZone) ([]handlerWrapper, map[string]nbdns.SimpleRecord, error) {
	var muxUpdates []handlerWrapper
	localRecords := make(map[string]nbdns.SimpleRecord, 0)

	for _, customZone := range customZones {
		if len(customZone.Records) == 0 {
			return nil, nil, fmt.Errorf("received an empty list of records")
		}

		muxUpdates = append(muxUpdates, handlerWrapper{
			domain:   customZone.Domain,
			handler:  s.localResolver,
			priority: PriorityMatchDomain,
		})

		for _, record := range customZone.Records {
			var class uint16 = dns.ClassINET
			if record.Class != nbdns.DefaultClass {
				return nil, nil, fmt.Errorf("received an invalid class type: %s", record.Class)
			}
			key := buildRecordKey(record.Name, class, uint16(record.Type))
			localRecords[key] = record
		}
	}
	return muxUpdates, localRecords, nil
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
		basePriority := PriorityMatchDomain
		if domainGroup.domain == nbdns.RootZone {
			basePriority = PriorityDefault
		}

		updates, err := s.createHandlersForDomainGroup(domainGroup, basePriority)
		if err != nil {
			return nil, err
		}
		muxUpdates = append(muxUpdates, updates...)
	}

	return muxUpdates, nil
}

func (s *DefaultServer) createHandlersForDomainGroup(domainGroup nsGroupsByDomain, basePriority int) ([]handlerWrapper, error) {
	var muxUpdates []handlerWrapper

	for i, nsGroup := range domainGroup.groups {
		// Decrement priority by handler index (0, 1, 2, ...) to avoid conflicts
		priority := basePriority - i

		// Check if we're about to overlap with the next priority tier
		if basePriority == PriorityMatchDomain && priority <= PriorityDefault {
			log.Warnf("too many handlers for domain=%s, would overlap with default priority tier (diff=%d). Skipping remaining handlers",
				domainGroup.domain, PriorityMatchDomain-PriorityDefault)
			break
		}

		log.Debugf("creating handler for domain=%s with priority=%d", domainGroup.domain, priority)
		handler, err := newUpstreamResolver(
			s.ctx,
			s.wgInterface.Name(),
			s.wgInterface.Address().IP,
			s.wgInterface.Address().Network,
			s.statusRecorder,
			s.hostsDNSHolder,
			domainGroup.domain,
		)
		if err != nil {
			return nil, fmt.Errorf("create upstream resolver: %v", err)
		}

		for _, ns := range nsGroup.NameServers {
			if ns.NSType != nbdns.UDPNameServerType {
				log.Warnf("skipping nameserver %s with type %s, this peer supports only %s",
					ns.IP.String(), ns.NSType.String(), nbdns.UDPNameServerType.String())
				continue
			}
			handler.upstreamServers = append(handler.upstreamServers, getNSHostPort(ns))
		}

		if len(handler.upstreamServers) == 0 {
			handler.stop()
			log.Errorf("received a nameserver group with an invalid nameserver list")
			continue
		}

		// when upstream fails to resolve domain several times over all it servers
		// it will calls this hook to exclude self from the configuration and
		// reapply DNS settings, but it not touch the original configuration and serial number
		// because it is temporal deactivation until next try
		//
		// after some period defined by upstream it tries to reactivate self by calling this hook
		// everything we need here is just to re-apply current configuration because it already
		// contains this upstream settings (temporal deactivation not removed it)
		handler.deactivate, handler.reactivate = s.upstreamCallbacks(nsGroup, handler, priority)

		muxUpdates = append(muxUpdates, handlerWrapper{
			domain:   domainGroup.domain,
			handler:  handler,
			priority: priority,
		})
	}

	return muxUpdates, nil
}

func (s *DefaultServer) updateMux(muxUpdates []handlerWrapper) {
	// this will introduce a short period of time when the server is not able to handle DNS requests
	for _, existing := range s.dnsMuxMap {
		s.deregisterHandler([]string{existing.domain}, existing.priority)
		existing.handler.stop()
	}

	muxUpdateMap := make(registeredHandlerMap)
	var containsRootUpdate bool

	for _, update := range muxUpdates {
		if update.domain == nbdns.RootZone {
			containsRootUpdate = true
		}
		s.registerHandler([]string{update.domain}, update.handler, update.priority)
		muxUpdateMap[update.handler.id()] = update
	}

	// If there's no root update and we had a root handler, restore it
	if !containsRootUpdate {
		for _, existing := range s.dnsMuxMap {
			if existing.domain == nbdns.RootZone {
				s.addHostRootZone()
				break
			}
		}
	}

	s.dnsMuxMap = muxUpdateMap
}

func (s *DefaultServer) updateLocalResolver(update map[string]nbdns.SimpleRecord) {
	for key := range s.localResolver.registeredMap {
		_, found := update[key]
		if !found {
			s.localResolver.deleteRecord(key)
		}
	}

	updatedMap := make(registrationMap)
	for key, record := range update {
		err := s.localResolver.registerRecord(record)
		if err != nil {
			log.Warnf("got an error while registering the record (%s), error: %v", record.String(), err)
		}
		updatedMap[key] = struct{}{}
	}

	s.localResolver.registeredMap = updatedMap
}

func getNSHostPort(ns nbdns.NameServer) string {
	return fmt.Sprintf("%s:%d", ns.IP.String(), ns.Port)
}

// upstreamCallbacks returns two functions, the first one is used to deactivate
// the upstream resolver from the configuration, the second one is used to
// reactivate it. Not allowed to call reactivate before deactivate.
func (s *DefaultServer) upstreamCallbacks(
	nsGroup *nbdns.NameServerGroup,
	handler dns.Handler,
	priority int,
) (deactivate func(error), reactivate func()) {
	var removeIndex map[string]int
	deactivate = func(err error) {
		s.mux.Lock()
		defer s.mux.Unlock()

		l := log.WithField("nameservers", nsGroup.NameServers)
		l.Info("Temporarily deactivating nameservers group due to timeout")

		removeIndex = make(map[string]int)
		for _, domain := range nsGroup.Domains {
			removeIndex[domain] = -1
		}
		if nsGroup.Primary {
			removeIndex[nbdns.RootZone] = -1
			s.currentConfig.RouteAll = false
			s.deregisterHandler([]string{nbdns.RootZone}, priority)
		}

		for i, item := range s.currentConfig.Domains {
			if _, found := removeIndex[item.Domain]; found {
				s.currentConfig.Domains[i].Disabled = true
				s.deregisterHandler([]string{item.Domain}, priority)
				removeIndex[item.Domain] = i
			}
		}

		if err := s.hostManager.applyDNSConfig(s.currentConfig, s.stateManager); err != nil {
			l.Errorf("Failed to apply nameserver deactivation on the host: %v", err)
		}

		go func() {
			if err := s.stateManager.PersistState(s.ctx); err != nil {
				l.Errorf("Failed to persist dns state: %v", err)
			}
		}()

		if runtime.GOOS == "android" && nsGroup.Primary && len(s.hostsDNSHolder.get()) > 0 {
			s.addHostRootZone()
		}

		s.updateNSState(nsGroup, err, false)
	}

	reactivate = func() {
		s.mux.Lock()
		defer s.mux.Unlock()

		for domain, i := range removeIndex {
			if i == -1 || i >= len(s.currentConfig.Domains) || s.currentConfig.Domains[i].Domain != domain {
				continue
			}
			s.currentConfig.Domains[i].Disabled = false
			s.registerHandler([]string{domain}, handler, priority)
		}

		l := log.WithField("nameservers", nsGroup.NameServers)
		l.Debug("reactivate temporary disabled nameserver group")

		if nsGroup.Primary {
			s.currentConfig.RouteAll = true
			s.registerHandler([]string{nbdns.RootZone}, handler, priority)
		}

		if s.hostManager != nil {
			if err := s.hostManager.applyDNSConfig(s.currentConfig, s.stateManager); err != nil {
				l.WithError(err).Error("reactivate temporary disabled nameserver group, DNS update apply")
			}
		}

		s.updateNSState(nsGroup, nil, true)
	}
	return
}

func (s *DefaultServer) addHostRootZone() {
	handler, err := newUpstreamResolver(
		s.ctx,
		s.wgInterface.Name(),
		s.wgInterface.Address().IP,
		s.wgInterface.Address().Network,
		s.statusRecorder,
		s.hostsDNSHolder,
		nbdns.RootZone,
	)
	if err != nil {
		log.Errorf("unable to create a new upstream resolver, error: %v", err)
		return
	}

	handler.upstreamServers = make([]string, 0)
	for k := range s.hostsDNSHolder.get() {
		handler.upstreamServers = append(handler.upstreamServers, k)
	}
	handler.deactivate = func(error) {}
	handler.reactivate = func() {}

	s.registerHandler([]string{nbdns.RootZone}, handler, PriorityDefault)
}

func (s *DefaultServer) updateNSGroupStates(groups []*nbdns.NameServerGroup) {
	var states []peer.NSGroupState

	for _, group := range groups {
		var servers []string
		for _, ns := range group.NameServers {
			servers = append(servers, fmt.Sprintf("%s:%d", ns.IP, ns.Port))
		}

		state := peer.NSGroupState{
			ID:      generateGroupKey(group),
			Servers: servers,
			Domains: group.Domains,
			// The probe will determine the state, default enabled
			Enabled: true,
			Error:   nil,
		}
		states = append(states, state)
	}
	s.statusRecorder.UpdateDNSStates(states)
}

func (s *DefaultServer) updateNSState(nsGroup *nbdns.NameServerGroup, err error, enabled bool) {
	states := s.statusRecorder.GetDNSStates()
	id := generateGroupKey(nsGroup)
	for i, state := range states {
		if state.ID == id {
			states[i].Enabled = enabled
			states[i].Error = err
			break
		}
	}
	s.statusRecorder.UpdateDNSStates(states)
}

func generateGroupKey(nsGroup *nbdns.NameServerGroup) string {
	var servers []string
	for _, ns := range nsGroup.NameServers {
		servers = append(servers, fmt.Sprintf("%s:%d", ns.IP, ns.Port))
	}
	return fmt.Sprintf("%v_%v", servers, nsGroup.Domains)
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
