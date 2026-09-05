//go:build ios

package NetBirdSDK

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	nbAnonymize "github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/netevents"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	types "github.com/netbirdio/netbird/upload-server/types"
)

// AnonymizeLevelDefault and AnonymizeLevelStrict are the accepted
// anonymizeLevel values for DebugBundle.
const (
	AnonymizeLevelDefault = nbAnonymize.LevelDefaultString
	AnonymizeLevelStrict  = nbAnonymize.LevelStrictString
)

var errClientAlreadyRunning = errors.New("client is already running")

// RouteListener export internal RouteListener for mobile
type NetworkChangeListener interface {
	listener.NetworkChangeListener
}

// DnsManager export internal dns Manager for mobile
type DnsManager interface {
	dns.IosDnsManager
}

// CustomLogger export internal CustomLogger for mobile
type CustomLogger interface {
	Debug(message string)
	Info(message string)
	Error(message string)
}

type selectRoute struct {
	NetID         string
	Network       netip.Prefix
	Domains       domain.List
	Selected      bool
	Status        string
	extraNetworks []netip.Prefix
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

// Client struct manage the life circle of background service
type Client struct {
	cfgFile               string
	stateFile             string
	cacheDir              string
	logFilePath           string
	recorder              *peer.Status
	deviceName            string
	osName                string
	osVersion             string
	networkChangeListener listener.NetworkChangeListener
	onHostDnsFn           func([]string)
	dnsManager            dns.IosDnsManager
	loginComplete         atomic.Bool
	// netMgr outlives engine restarts: it mirrors the OS connectivity, not
	// the engine lifecycle. Run injects its state and sweeper into each new
	// ConnectClient.
	netMgr *netevents.Manager
	// preloadedConfig holds config loaded from JSON (used on tvOS where file writes are blocked)
	preloadedConfig *profilemanager.Config

	// stateMu guards the run lifecycle as one unit: the cancel installed by
	// the current run, the channel it closes on exit, and the state it
	// published. One run at a time: startRun refuses a second Run while the
	// previous one has not exited, and the platform serializes Stop before
	// Start, so no generation tracking is needed.
	stateMu       sync.RWMutex
	connectClient *internal.ConnectClient
	config        *profilemanager.Config
	runDone       chan struct{}
	ctxCancel     context.CancelFunc
}

// NewClient instantiate a new Client
func NewClient(cfgFile, stateFile, cacheDir, logFilePath, deviceName string, osVersion string, osName string, networkChangeListener NetworkChangeListener, dnsManager DnsManager) *Client {
	recorder := peer.NewRecorder("")
	return &Client{
		cfgFile:               cfgFile,
		stateFile:             stateFile,
		cacheDir:              cacheDir,
		logFilePath:           logFilePath,
		deviceName:            deviceName,
		osName:                osName,
		osVersion:             osVersion,
		recorder:              recorder,
		networkChangeListener: networkChangeListener,
		dnsManager:            dnsManager,
		netMgr:                netevents.NewManager(recorder),
	}
}

// SetConfigFromJSON loads config from a JSON string into memory.
// This is used on tvOS where file writes to App Group containers are blocked.
// When set, IsLoginRequired() and Run() will use this preloaded config instead of reading from file.
func (c *Client) SetConfigFromJSON(jsonStr string) error {
	cfg, err := profilemanager.ConfigFromJSON(jsonStr)
	if err != nil {
		log.Errorf("SetConfigFromJSON: failed to parse config JSON: %v", err)
		return err
	}
	c.preloadedConfig = cfg
	log.Infof("SetConfigFromJSON: config loaded successfully from JSON")
	return nil
}

// Run start the internal client. It is a blocker function
func (c *Client) Run(fd int32, interfaceName string, envList *EnvList) error {
	exportEnvList(envList)
	log.Infof("Starting NetBird client")
	log.Debugf("Tunnel uses interface: %s", interfaceName)

	var cfg *profilemanager.Config
	var err error

	// Use preloaded config if available (tvOS where file writes are blocked)
	if c.preloadedConfig != nil {
		log.Infof("Run: using preloaded config from memory")
		cfg = c.preloadedConfig
	} else {
		log.Infof("Run: loading config from file")
		// Use DirectUpdateOrCreateConfig to avoid atomic file operations (temp file + rename)
		// which are blocked by the tvOS sandbox in App Group containers
		cfg, err = profilemanager.DirectUpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath:    c.cfgFile,
			StateFilePath: c.stateFile,
		})
		if err != nil {
			return err
		}
	}
	c.recorder.UpdateManagementAddress(cfg.ManagementURL.String())
	c.recorder.UpdateRosenpass(cfg.RosenpassEnabled, cfg.RosenpassPermissive)

	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsNameCtxKey, c.osName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsVersionCtxKey, c.osVersion)
	runCtx, runCancel := context.WithCancel(ctxWithValues)
	defer runCancel()

	done, err := c.startRun(runCancel)
	if err != nil {
		return err
	}
	defer c.finishRun(done)
	ctx := runCtx

	// No login pre-flight here. The engine's own loginToManagement (connect.go) performs
	// the authoritative Login immediately before the first Sync, so a LoginSync() call at
	// this point only duplicated it — costing two extra Login RPCs (IsLoginRequired +
	// Login) on every engine start, since IsLoginRequired is itself a full Login RPC.
	//
	// Auth failures still reach the caller through the engine path: loginToManagement
	// returns PermissionDenied, which marks the shared status recorder
	// (MarkManagementDisconnected) and fires ClientStop → onDisconnected, where
	// IsLoginRequiredCached() reports login-required. The error is also returned out of Run().
	//
	// A pre-flight was also actively harmful when the server is unreachable: its 2-minute
	// backoff blocked the start and then reported "login required" for what was really a
	// timeout. The engine instead keeps retrying and recovers when the server returns.
	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	c.onHostDnsFn = func([]string) {}
	cfg.WgIface = interfaceName

	connectClient := internal.NewConnectClient(ctx, cfg, c.recorder,
		internal.WithNetEvents(c.netMgr))
	c.setState(cfg, connectClient)
	// Persist the latest sync response so DebugBundle can include the network
	// map. On iOS this is backed by disk to keep it out of the constrained
	// process memory (see the syncstore package).
	connectClient.SetSyncResponsePersistence(true)
	return connectClient.RunOniOS(fd, c.networkChangeListener, c.dnsManager, c.stateFile, c.cacheDir, c.logFilePath)
}

// SetNetworkAvailable feeds OS-reported network availability into the client
// (e.g. from NWPathMonitor). While unavailable, the internal reconnect loops
// suspend their attempts and the connection listener reports NoNetwork
// instead of Connecting; when availability returns, the loops resume
// immediately with a fresh backoff. Losing the last network also sweeps the
// registered connections, so the client does not keep reporting Connected
// over stale sockets with no network at all.
func (c *Client) SetNetworkAvailable(available bool) {
	c.netMgr.SetNetworkAvailable(available)
}

// NotifyNetworkChange marks the management, signal and relay connections
// stale after the OS switched networks and schedules a sweep that cuts
// whatever has not redialed on the new network by then. The engine and the
// TUN device stay untouched.
func (c *Client) NotifyNetworkChange() {
	c.netMgr.NotifyNetworkChange()
}

// Stop cancels the running client and waits for the run loop to exit, so a
// caller that restarts immediately cannot race the outgoing teardown.
func (c *Client) Stop() {
	done := c.cancelRun()
	if done == nil {
		return
	}

	select {
	case <-done:
	case <-time.After(stopRunWaitTimeout):
		log.Warnf("Stop: timed out waiting for the run loop to exit")
	}
}

// StopWithoutWait cancels the running client without waiting for the run loop.
// Use it where the caller is on a deadline the wait could overrun, such as
// NEPacketTunnelProvider.stopTunnel, which iOS gives only a few seconds
// before it kills the extension.
func (c *Client) StopWithoutWait() {
	c.cancelRun()
}

func (c *Client) cancelRun() chan struct{} {
	c.stateMu.RLock()
	done := c.runDone
	cancel := c.ctxCancel
	c.stateMu.RUnlock()

	if cancel != nil {
		cancel()
	}

	return done
}

// DebugBundle generates a debug bundle, uploads it and returns the upload key.
// It works with or without a running engine: when the engine is up it reuses
// the live config, sync response and client metrics; otherwise it loads the
// config from disk (or the preloaded tvOS config). anonymizeLevel is "default"
// or "strict"; strict also anonymizes internal IP ranges, peer names, and
// WireGuard public keys, and implies anonymize.
func (c *Client) DebugBundle(anonymize bool, anonymizeLevel string) (string, error) {
	cfg, cc := c.stateSnapshot()

	// If the engine hasn't been started, load config so we can reach management.
	if cfg == nil {
		if c.preloadedConfig != nil {
			cfg = c.preloadedConfig
		} else {
			var err error
			// Use DirectUpdateOrCreateConfig to avoid atomic file operations
			// (temp file + rename) blocked by the tvOS sandbox.
			cfg, err = profilemanager.DirectUpdateOrCreateConfig(profilemanager.ConfigInput{
				ConfigPath:    c.cfgFile,
				StateFilePath: c.stateFile,
			})
			if err != nil {
				return "", fmt.Errorf("load config: %w", err)
			}
		}
	}

	deps := debug.GeneratorDependencies{
		InternalConfig: cfg,
		StatusRecorder: c.recorder,
		TempDir:        c.cacheDir,
		StatePath:      c.stateFile,
		LogPath:        c.logFilePath,
	}

	if cc != nil {
		resp, err := cc.GetLatestSyncResponse()
		if err != nil {
			log.Warnf("get latest sync response: %v", err)
		}
		deps.SyncResponse = resp

		if e := cc.Engine(); e != nil {
			deps.RefreshStatus = func() {
				e.RunHealthProbes(context.Background(), true)
			}
			if cm := e.GetClientMetrics(); cm != nil {
				deps.ClientMetrics = cm
			}
		}
	}

	bundleGenerator := debug.NewBundleGenerator(
		deps,
		debug.BundleConfig{
			Anonymize:         anonymize,
			AnonymizeLevel:    nbAnonymize.ParseLevel(anonymizeLevel),
			IncludeSystemInfo: true,
		},
	)

	path, err := bundleGenerator.Generate()
	if err != nil {
		return "", fmt.Errorf("generate debug bundle: %w", err)
	}
	defer func() {
		if err := os.Remove(path); err != nil {
			log.Errorf("failed to remove debug bundle file: %v", err)
		}
	}()

	uploadCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	key, err := debug.UploadDebugBundle(uploadCtx, types.DefaultBundleURL, cfg.ManagementURL.String(), path, false)
	if err != nil {
		return "", fmt.Errorf("upload debug bundle: %w", err)
	}

	log.Infof("debug bundle uploaded with key %s", key)
	return key, nil
}

// SetTraceLogLevel configure the logger to trace level
func (c *Client) SetTraceLogLevel() {
	log.SetLevel(log.TraceLevel)
}

// GetStatusDetails return with the list of the PeerInfos
func (c *Client) GetStatusDetails() *StatusDetails {

	fullStatus := c.recorder.GetFullStatus()

	peerInfos := make([]PeerInfo, len(fullStatus.Peers))
	for n, p := range fullStatus.Peers {
		var routes = RoutesDetails{}
		for r := range p.GetRoutes() {
			routeInfo := RoutesInfo{r}
			routes.items = append(routes.items, routeInfo)
		}
		pi := PeerInfo{
			IP:                         p.IP,
			IPv6:                       p.IPv6,
			FQDN:                       p.FQDN,
			LocalIceCandidateEndpoint:  p.LocalIceCandidateEndpoint,
			RemoteIceCandidateEndpoint: p.RemoteIceCandidateEndpoint,
			LocalIceCandidateType:      p.LocalIceCandidateType,
			RemoteIceCandidateType:     p.RemoteIceCandidateType,
			PubKey:                     p.PubKey,
			Latency:                    formatDuration(p.Latency),
			BytesRx:                    p.BytesRx,
			BytesTx:                    p.BytesTx,
			ConnStatus:                 p.ConnStatus.String(),
			ConnStatusUpdate:           p.ConnStatusUpdate.Format("2006-01-02 15:04:05"),
			LastWireguardHandshake:     p.LastWireguardHandshake.String(),
			Relayed:                    p.Relayed,
			RosenpassEnabled:           p.RosenpassEnabled,
			Routes:                     routes,
		}
		peerInfos[n] = pi
	}
	return &StatusDetails{items: peerInfos, fqdn: fullStatus.LocalPeerState.FQDN, ip: fullStatus.LocalPeerState.IP, ipv6: fullStatus.LocalPeerState.IPv6}
}

// SetConnectionListener set the network connection listener
func (c *Client) SetConnectionListener(listener ConnectionListener) {
	if listener == nil {
		c.recorder.RemoveConnectionListener()
		return
	}
	c.recorder.SetConnectionListener(connectionListenerAdapter{listener})
}

// RemoveConnectionListener remove connection listener
func (c *Client) RemoveConnectionListener() {
	c.recorder.RemoveConnectionListener()
}

// IsLoginRequiredCached reports whether the LAST observed management error was an
// auth failure (PermissionDenied/InvalidArgument), using the in-memory status
// recorder. Unlike IsLoginRequired() it performs NO network call, so it is safe to
// call from the connection listener during teardown (e.g. onDisconnected) without
// blocking on a slow or unavailable network. Returns false while connected to
// management or when the last error was not auth-related.
func (c *Client) IsLoginRequiredCached() bool {
	return c.recorder.IsLoginRequired()
}

func (c *Client) IsLoginRequired() bool {
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsNameCtxKey, c.osName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsVersionCtxKey, c.osVersion)
	ctx, cancel := context.WithCancel(ctxWithValues)
	defer cancel()

	var cfg *profilemanager.Config
	var err error

	// Use preloaded config if available (tvOS where file writes are blocked)
	if c.preloadedConfig != nil {
		log.Infof("IsLoginRequired: using preloaded config from memory")
		cfg = c.preloadedConfig
	} else {
		log.Infof("IsLoginRequired: loading config from file")
		// Use DirectUpdateOrCreateConfig to avoid atomic file operations (temp file + rename)
		// which are blocked by the tvOS sandbox in App Group containers
		cfg, err = profilemanager.DirectUpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath: c.cfgFile,
		})
		if err != nil {
			log.Errorf("IsLoginRequired: failed to load config: %v", err)
			// If we can't load config, assume login is required
			return true
		}
	}

	if cfg == nil {
		log.Errorf("IsLoginRequired: config is nil")
		return true
	}

	authClient, err := auth.NewAuth(ctx, cfg.PrivateKey, cfg.ManagementURL, cfg)
	if err != nil {
		log.Errorf("IsLoginRequired: failed to create auth client: %v", err)
		return true // Assume login is required if we can't create auth client
	}
	defer authClient.Close()

	needsLogin, err := authClient.IsLoginRequired(ctx)
	if err != nil {
		log.Errorf("IsLoginRequired: check failed: %v", err)
		// If the check fails, assume login is required to be safe
		return true
	}
	log.Infof("IsLoginRequired: needsLogin=%v", needsLogin)
	return needsLogin
}

// loginForMobileAuthTimeout is the timeout for requesting auth info from the server
const loginForMobileAuthTimeout = 30 * time.Second

const stopRunWaitTimeout = 20 * time.Second

func (c *Client) LoginForMobile() string {
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsNameCtxKey, c.osName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsVersionCtxKey, c.osVersion)
	ctx, cancel := context.WithCancel(ctxWithValues)
	loginDone := false
	defer func() {
		if !loginDone {
			cancel()
		}
	}()

	// Use DirectUpdateOrCreateConfig to avoid atomic file operations (temp file + rename)
	// which are blocked by the tvOS sandbox in App Group containers
	cfg, err := profilemanager.DirectUpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath: c.cfgFile,
	})
	if err != nil {
		log.Errorf("LoginForMobile: failed to load config: %v", err)
		return fmt.Sprintf("failed to load config: %v", err)
	}

	oAuthFlow, err := auth.NewOAuthFlow(ctx, cfg, false, false, "")
	if err != nil {
		return err.Error()
	}

	// Use a bounded timeout for the auth info request to prevent indefinite hangs
	authInfoCtx, authInfoCancel := context.WithTimeout(ctx, loginForMobileAuthTimeout)
	defer authInfoCancel()

	flowInfo, err := oAuthFlow.RequestAuthInfo(authInfoCtx)
	if err != nil {
		return err.Error()
	}

	// This could cause a potential race condition with loading the extension which need to be handled on swift side
	loginDone = true
	go func() {
		defer cancel()
		tokenInfo, err := oAuthFlow.WaitToken(ctx, flowInfo)
		if err != nil {
			log.Errorf("LoginForMobile: WaitToken failed: %v", err)
			return
		}
		jwtToken := tokenInfo.GetTokenToUse()
		authClient, err := auth.NewAuth(ctx, cfg.PrivateKey, cfg.ManagementURL, cfg)
		if err != nil {
			log.Errorf("LoginForMobile: failed to create auth client: %v", err)
			return
		}
		defer authClient.Close()
		if err, _ := authClient.Login(ctx, "", jwtToken); err != nil {
			log.Errorf("LoginForMobile: Login failed: %v", err)
			return
		}
		c.loginComplete.Store(true)
	}()

	return flowInfo.VerificationURIComplete
}

func (c *Client) IsLoginComplete() bool {
	return c.loginComplete.Load()
}

func (c *Client) ClearLoginComplete() {
	c.loginComplete.Store(false)
}

func (c *Client) GetRoutesSelectionDetails() (*RoutesSelectionDetails, error) {
	_, connectClient := c.stateSnapshot()
	if connectClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	if routeManager == nil {
		return nil, fmt.Errorf("could not get route manager")
	}
	routesMap := routeManager.GetClientRoutesWithNetID()
	routeSelector := routeManager.GetRouteSelector()
	if routeSelector == nil {
		return nil, fmt.Errorf("could not get route selector")
	}

	v6ExitMerged := route.V6ExitMergeSet(routesMap)
	routes := buildSelectRoutes(routesMap, routeSelector.IsSelected, v6ExitMerged)
	resolvedDomains := c.recorder.GetResolvedDomainsStates()

	// Compute each route's connection status in the core (mirroring the Android
	// bridge), so the UI doesn't have to infer it by string-matching the joined
	// Network value against peer routes. For a merged exit node the status reflects
	// whichever of the v4/v6 prefixes is served by a connected peer; for dynamic
	// (DNS) routes the peer route key is the domain pattern (see dynamic.Route.String).
	connectedRoutes := c.connectedRouteSet()
	for _, r := range routes {
		r.Status = routeStatus(r, connectedRoutes)
	}

	return prepareRouteSelectionDetails(routes, resolvedDomains), nil
}

// connectedRouteSet returns the set of route keys (as strings) currently served by a
// connected peer, gathered across all connected peers' route tables. The keys match
// what the route manager records: a prefix string for static routes (e.g. "0.0.0.0/0")
// and the domain pattern for dynamic routes (e.g. "*.example.com").
func (c *Client) connectedRouteSet() map[string]struct{} {
	connected := map[string]struct{}{}
	for _, p := range c.recorder.GetFullStatus().Peers {
		if p.ConnStatus != peer.StatusConnected {
			continue
		}
		for r := range p.GetRoutes() {
			connected[r] = struct{}{}
		}
	}
	return connected
}

// routeStatus reports "Connected" if any of the route's keys is served by a connected
// peer: the primary Network prefix, an extra v6 network of a merged exit node, or the
// domain pattern for a dynamic DNS route. Otherwise "Idle".
func routeStatus(r *selectRoute, connectedRoutes map[string]struct{}) string {
	keys := make([]string, 0, 1+len(r.extraNetworks))
	if len(r.Domains) > 0 {
		keys = append(keys, r.Domains.SafeString())
	} else {
		keys = append(keys, r.Network.String())
	}
	for _, extra := range r.extraNetworks {
		keys = append(keys, extra.String())
	}
	for _, k := range keys {
		if _, ok := connectedRoutes[k]; ok {
			return peer.StatusConnected.String()
		}
	}
	return peer.StatusIdle.String()
}

func buildSelectRoutes(routesMap map[route.NetID][]*route.Route, isSelected func(route.NetID) bool, v6Merged map[route.NetID]struct{}) []*selectRoute {
	var routes []*selectRoute
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		if _, ok := v6Merged[id]; ok {
			continue
		}

		r := &selectRoute{
			NetID:    string(id),
			Network:  rt[0].Network,
			Domains:  rt[0].Domains,
			Selected: isSelected(id),
		}

		v6ID := route.NetID(string(id) + route.V6ExitSuffix)
		if _, ok := v6Merged[v6ID]; ok {
			r.extraNetworks = []netip.Prefix{routesMap[v6ID][0].Network}
		}

		routes = append(routes, r)
	}

	sort.Slice(routes, func(i, j int) bool {
		iBits, jBits := routes[i].Network.Bits(), routes[j].Network.Bits()
		if iBits != jBits {
			return iBits < jBits
		}
		iAddr, jAddr := routes[i].Network.Addr(), routes[j].Network.Addr()
		if iAddr != jAddr {
			return iAddr.Less(jAddr)
		}
		return routes[i].NetID < routes[j].NetID
	})

	return routes
}

func prepareRouteSelectionDetails(routes []*selectRoute, resolvedDomains map[domain.Domain]peer.ResolvedDomainInfo) *RoutesSelectionDetails {
	var routeSelection []RoutesSelectionInfo
	for _, r := range routes {
		// resolvedDomains is keyed by the resolved domain (e.g. api.ipify.org),
		// not the configured pattern (e.g. *.ipify.org). Group entries whose
		// ParentDomain belongs to this route, mirroring the daemon logic in
		// client/server/network.go.
		domainList := make([]DomainInfo, 0, len(r.Domains))
		domainIndex := make(map[domain.Domain]int, len(r.Domains))
		for _, d := range r.Domains {
			domainIndex[d] = len(domainList)
			domainList = append(domainList, DomainInfo{Domain: d.SafeString()})
		}

		for _, info := range resolvedDomains {
			idx, ok := domainIndex[info.ParentDomain]
			if !ok {
				continue
			}
			for _, prefix := range info.Prefixes {
				domainList[idx].AddResolvedIP(prefix.Addr().String())
			}
		}

		domainDetails := DomainDetails{items: domainList}

		// For dynamic (DNS) routes, expose the joined domain pattern as the
		// Network value so it matches the peer.routes entries on the Swift
		// side (mirroring the Android bridge in client/android/client.go).
		netStr := r.Network.String()
		if len(r.Domains) > 0 {
			netStr = r.Domains.SafeString()
		}
		for _, extra := range r.extraNetworks {
			netStr += ", " + extra.String()
		}

		routeSelection = append(routeSelection, RoutesSelectionInfo{
			ID:       r.NetID,
			Network:  netStr,
			Domains:  &domainDetails,
			Selected: r.Selected,
			Status:   r.Status,
		})
	}

	routeSelectionDetails := RoutesSelectionDetails{items: routeSelection}
	return &routeSelectionDetails
}

func (c *Client) SelectRoute(id string) error {
	_, connectClient := c.stateSnapshot()
	if connectClient == nil {
		return fmt.Errorf("not connected")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	if id == "All" {
		log.Debugf("select all routes")
		routeManager.SelectAllRoutes()
		return nil
	}

	log.Debugf("select route with id: %s", id)
	if err := routeManager.SelectRoutes(toNetIDs([]string{id}), true); err != nil {
		log.Debugf("error when selecting routes: %s", err)
		return err
	}
	return nil
}

func (c *Client) DeselectRoute(id string) error {
	_, connectClient := c.stateSnapshot()
	if connectClient == nil {
		return fmt.Errorf("not connected")
	}
	engine := connectClient.Engine()
	if engine == nil {
		return fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	if id == "All" {
		log.Debugf("deselect all routes")
		routeManager.DeselectAllRoutes()
		return nil
	}

	log.Debugf("deselect route with id: %s", id)
	if err := routeManager.DeselectRoutes(toNetIDs([]string{id})); err != nil {
		log.Debugf("error when deselecting routes: %s", err)
		return err
	}
	return nil
}

func (c *Client) startRun(cancel context.CancelFunc) (chan struct{}, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	if c.runDone != nil {
		return nil, errClientAlreadyRunning
	}

	done := make(chan struct{})
	c.runDone = done
	c.ctxCancel = cancel
	return done, nil
}

func (c *Client) finishRun(done chan struct{}) {
	c.stateMu.Lock()
	c.connectClient = nil
	c.config = nil
	c.runDone = nil
	c.ctxCancel = nil
	c.stateMu.Unlock()

	close(done)
}

func (c *Client) setState(cfg *profilemanager.Config, cc *internal.ConnectClient) {
	c.stateMu.Lock()
	c.config = cfg
	c.connectClient = cc
	c.stateMu.Unlock()
}

// stateSnapshot returns the current config and ConnectClient under the lock.
func (c *Client) stateSnapshot() (*profilemanager.Config, *internal.ConnectClient) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.config, c.connectClient
}

func formatDuration(d time.Duration) string {
	ds := d.String()
	dotIndex := strings.Index(ds, ".")
	if dotIndex != -1 {
		// Determine end of numeric part, ensuring we stop at two decimal places or the actual end if fewer
		endIndex := dotIndex + 3
		if endIndex > len(ds) {
			endIndex = len(ds)
		}
		// Find where the numeric part ends by finding the first non-digit character after the dot
		unitStart := endIndex
		for unitStart < len(ds) && (ds[unitStart] >= '0' && ds[unitStart] <= '9') {
			unitStart++
		}
		// Ensures that we only take the unit characters after the numerical part
		if unitStart < len(ds) {
			return ds[:endIndex] + ds[unitStart:]
		}
		return ds[:endIndex] // In case no units are found after the digits
	}
	return ds
}

func toNetIDs(routes []string) []route.NetID {
	var netIDs []route.NetID
	for _, rt := range routes {
		netIDs = append(netIDs, route.NetID(rt))
	}
	return netIDs
}

func exportEnvList(list *EnvList) {
	if list == nil {
		return
	}
	for k, v := range list.AllItems() {
		log.Debugf("Env variable %s's value is currently: %s", k, os.Getenv(k))
		log.Debugf("Setting env variable %s: %s", k, v)

		if err := os.Setenv(k, v); err != nil {
			log.Errorf("could not set env variable %s: %v", k, err)
		} else {
			log.Debugf("Env variable %s was set successfully", k)
		}
	}
}
