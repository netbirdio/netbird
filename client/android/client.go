//go:build android

package android

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/netstate"
	"github.com/netbirdio/netbird/client/netsweep"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	types "github.com/netbirdio/netbird/upload-server/types"
)

// TunAdapter export internal TunAdapter for mobile
type TunAdapter interface {
	device.TunAdapter
}

// IFaceDiscover export internal IFaceDiscover for mobile
type IFaceDiscover interface {
	stdnet.ExternalIFaceDiscover
}

// NetworkChangeListener export internal NetworkChangeListener for mobile
type NetworkChangeListener interface {
	listener.NetworkChangeListener
}

// DnsReadyListener export internal dns ReadyListener for mobile
type DnsReadyListener interface {
	dns.ReadyListener
}

// TunSettings is a snapshot of the settings the TUN device is rebuilt with
type TunSettings struct {
	Routes        string
	SearchDomains string
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

// Client struct manage the life circle of background service
type Client struct {
	tunAdapter            device.TunAdapter
	iFaceDiscover         IFaceDiscover
	recorder              *peer.Status
	ctxCancel             context.CancelFunc
	ctxCancelLock         *sync.Mutex
	deviceName            string
	uiVersion             string
	networkChangeListener listener.NetworkChangeListener
	// netState outlives engine restarts: it mirrors the OS connectivity, not
	// the engine lifecycle. Run and RunWithoutLogin inject it into each new
	// ConnectClient, which distributes it to every reconnection loop.
	netState *netstate.State

	// sweeper also outlives engine restarts; NotifyNetworkChange sweeps it.
	sweeper *netsweep.Sweeper

	stateMu       sync.RWMutex
	connectClient *internal.ConnectClient
	config        *profilemanager.Config
	cacheDir      string
	// Identifies the running profile for the SSO login hint; see profile_state.go.
	cfgPath string

	stateChangeMu    sync.Mutex
	stateChangeSubID string
	eventSub         *peer.EventSubscription
	// Closed to stop the watch goroutines from delivering buffered items to a
	// listener that has been removed or replaced. See stopStateChangeWatchLocked.
	stateChangeDone chan struct{}

	// Latched "the server wants an interactive login": survives the engine
	// restarts that replace the run loop's context state. See Client.Status.
	// Guarded by loginRequiredMu together with loginCleared, which counts
	// clears so a stale observation cannot re-latch over one.
	loginRequiredMu sync.Mutex
	loginRequired   bool
	loginCleared    uint64

	extendMu     sync.Mutex
	extendCancel context.CancelFunc
}

func (c *Client) setState(cfg *profilemanager.Config, cacheDir string, cfgPath string, cc *internal.ConnectClient) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.config = cfg
	c.cacheDir = cacheDir
	c.cfgPath = cfgPath
	c.connectClient = cc
}

func (c *Client) stateSnapshot() (*profilemanager.Config, string, *internal.ConnectClient) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.config, c.cacheDir, c.connectClient
}

// authSnapshot returns the config together with the path it was loaded from, in
// one lock: the path identifies the profile whose account email backs the login
// hint, so reading it separately could pair one profile's config with another's
// hint when a profile switch lands in between.
func (c *Client) authSnapshot() (*profilemanager.Config, string, *internal.ConnectClient) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.config, c.cfgPath, c.connectClient
}

func (c *Client) getConnectClient() *internal.ConnectClient {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.connectClient
}

// NewClient instantiate a new Client
func NewClient(androidSDKVersion int, deviceName string, uiVersion string, tunAdapter TunAdapter, iFaceDiscover IFaceDiscover, networkChangeListener NetworkChangeListener) *Client {
	execWorkaround(androidSDKVersion)

	net.SetAndroidProtectSocketFn(tunAdapter.ProtectSocket)
	return &Client{
		deviceName:            deviceName,
		uiVersion:             uiVersion,
		tunAdapter:            tunAdapter,
		iFaceDiscover:         iFaceDiscover,
		recorder:              peer.NewRecorder(""),
		ctxCancelLock:         &sync.Mutex{},
		networkChangeListener: networkChangeListener,
		netState:              netstate.New(),
		sweeper:               netsweep.New(),
	}
}

// SetNetworkAvailable feeds OS-reported network availability into the client.
// While unavailable, the internal reconnect loops suspend their attempts and
// the connection listener reports NoNetwork instead of Connecting; when
// availability returns, the loops resume immediately with a fresh backoff.
func (c *Client) SetNetworkAvailable(available bool) {
	c.netState.Set(available)
	c.recorder.SetNetworkAvailable(available)
}

// NotifyNetworkChange cuts the management, signal and relay connections
// after the OS switched networks, so the reconnect loops redial immediately
// on the new one. The engine and the TUN device stay untouched.
func (c *Client) NotifyNetworkChange() {
	n := c.sweeper.Sweep()
	log.Infof("network change: swept %d connections", n)
}

// Run start the internal client. It is a blocker function
func (c *Client) Run(platformFiles PlatformFiles, urlOpener URLOpener, isAndroidTV bool, dns *DNSList, dnsReadyListener DnsReadyListener, envList *EnvList) error {
	exportEnvList(envList)

	cfgFile := platformFiles.ConfigurationFilePath()
	stateFile := platformFiles.StateFilePath()
	cacheDir := platformFiles.CacheDir()

	log.Infof("Starting client with config: %s, state: %s", cfgFile, stateFile)

	cfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath: cfgFile,
	})
	if err != nil {
		return err
	}
	c.recorder.UpdateManagementAddress(cfg.ManagementURL.String())
	c.recorder.UpdateRosenpass(cfg.RosenpassEnabled, cfg.RosenpassPermissive)

	var ctx context.Context
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.UiVersionCtxKey, c.uiVersion)

	c.ctxCancelLock.Lock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)
	defer c.ctxCancel()
	c.ctxCancelLock.Unlock()

	auth := NewAuthWithConfig(ctx, cfg, cfgFile)
	err = auth.login(urlOpener, isAndroidTV)
	if err != nil {
		return err
	}
	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	connectClient := internal.NewConnectClient(ctx, cfg, c.recorder,
		internal.WithNetworkState(c.netState), internal.WithSweeper(c.sweeper))
	c.setState(cfg, cacheDir, cfgFile, connectClient)
	// This path runs the interactive SSO flow, so reaching here means the peer
	// is authenticated again — release the latch Status() reports from. Clear
	// only once the fresh connect client is installed: until then Status()
	// still reads the previous run's context state, which holds the NeedsLogin
	// that prompted this login, and would re-latch what was just cleared.
	c.clearLoginRequired()
	return connectClient.RunOnAndroid(c.tunAdapter, c.iFaceDiscover, c.networkChangeListener, slices.Clone(dns.items), dnsReadyListener, stateFile, cacheDir)
}

// RunWithoutLogin we apply this type of run function when the backed has been started without UI (i.e. after reboot).
// In this case make no sense handle registration steps.
func (c *Client) RunWithoutLogin(platformFiles PlatformFiles, dns *DNSList, dnsReadyListener DnsReadyListener, envList *EnvList) error {
	exportEnvList(envList)

	cfgFile := platformFiles.ConfigurationFilePath()
	stateFile := platformFiles.StateFilePath()
	cacheDir := platformFiles.CacheDir()

	log.Infof("Starting client without login with config: %s, state: %s", cfgFile, stateFile)

	cfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath: cfgFile,
	})
	if err != nil {
		return err
	}
	c.recorder.UpdateManagementAddress(cfg.ManagementURL.String())
	c.recorder.UpdateRosenpass(cfg.RosenpassEnabled, cfg.RosenpassPermissive)

	var ctx context.Context
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	c.ctxCancelLock.Lock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)
	defer c.ctxCancel()
	c.ctxCancelLock.Unlock()

	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	connectClient := internal.NewConnectClient(ctx, cfg, c.recorder,
		internal.WithNetworkState(c.netState), internal.WithSweeper(c.sweeper))
	c.setState(cfg, cacheDir, cfgFile, connectClient)
	return connectClient.RunOnAndroid(c.tunAdapter, c.iFaceDiscover, c.networkChangeListener, slices.Clone(dns.items), dnsReadyListener, stateFile, cacheDir)
}

// Stop the internal client and free the resources
func (c *Client) Stop() {
	c.ctxCancelLock.Lock()
	defer c.ctxCancelLock.Unlock()
	if c.ctxCancel == nil {
		return
	}

	c.ctxCancel()
}

func (c *Client) RenewTun(fd int) error {
	cc := c.getConnectClient()
	if cc == nil {
		return fmt.Errorf("engine not running")
	}

	e := cc.Engine()
	if e == nil {
		return fmt.Errorf("engine not initialized")
	}

	return e.RenewTun(fd)
}

func (c *Client) GetTunSettings() (*TunSettings, error) {
	cc := c.getConnectClient()
	if cc == nil {
		return nil, fmt.Errorf("engine not running")
	}

	e := cc.Engine()
	if e == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	routes, searchDomains := e.TunSettings()
	return &TunSettings{
		Routes:        strings.Join(routes, ";"),
		SearchDomains: strings.Join(searchDomains, ";"),
	}, nil
}

// DebugBundle generates a debug bundle, uploads it, and returns the upload key.
// It works both with and without a running engine.
func (c *Client) DebugBundle(platformFiles PlatformFiles, anonymize bool) (string, error) {
	cfg, cacheDir, cc := c.stateSnapshot()

	// If the engine hasn't been started, load config from disk
	if cfg == nil {
		var err error
		cfg, err = profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath: platformFiles.ConfigurationFilePath(),
		})
		if err != nil {
			return "", fmt.Errorf("load config: %w", err)
		}
		cacheDir = platformFiles.CacheDir()
	}

	deps := debug.GeneratorDependencies{
		InternalConfig: cfg,
		StatusRecorder: c.recorder,
		TempDir:        cacheDir,
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

// SetInfoLogLevel configure the logger to info level
func (c *Client) SetInfoLogLevel() {
	log.SetLevel(log.InfoLevel)
}

// PeersList return with the list of the PeerInfos
func (c *Client) PeersList() *PeerInfoArray {

	// The recorder only caches transfer counters and handshake times; nothing
	// refreshes them on its own, so without this they read as zero. The desktop
	// daemon does the same before serving a full peer status.
	if err := c.recorder.RefreshWireGuardStats(); err != nil {
		log.Debugf("failed to refresh WireGuard stats: %v", err)
	}

	fullStatus := c.recorder.GetFullStatus()

	peerInfos := make([]PeerInfo, len(fullStatus.Peers))
	for n, p := range fullStatus.Peers {
		pi := PeerInfo{
			IP:         p.IP,
			IPv6:       p.IPv6,
			FQDN:       p.FQDN,
			ConnStatus: int(p.ConnStatus),
			Routes:     PeerRoutes{routes: maps.Keys(p.GetRoutes())},

			PubKey:                     p.PubKey,
			Latency:                    formatDuration(p.Latency),
			LatencyMs:                  p.Latency.Milliseconds(),
			BytesRx:                    p.BytesRx,
			BytesTx:                    p.BytesTx,
			ConnStatusUpdate:           formatTime(p.ConnStatusUpdate),
			Relayed:                    p.Relayed,
			RosenpassEnabled:           p.RosenpassEnabled,
			LastWireguardHandshake:     formatTime(p.LastWireguardHandshake),
			LocalIceCandidateType:      p.LocalIceCandidateType,
			RemoteIceCandidateType:     p.RemoteIceCandidateType,
			LocalIceCandidateEndpoint:  p.LocalIceCandidateEndpoint,
			RemoteIceCandidateEndpoint: p.RemoteIceCandidateEndpoint,
		}
		peerInfos[n] = pi
	}
	return &PeerInfoArray{items: peerInfos}
}

func (c *Client) Networks() *NetworkArray {
	cc := c.getConnectClient()
	if cc == nil {
		log.Error("not connected")
		return nil
	}

	engine := cc.Engine()
	if engine == nil {
		log.Error("could not get engine")
		return nil
	}

	routeManager := engine.GetRouteManager()
	if routeManager == nil {
		log.Error("could not get route manager")
		return nil
	}

	routeSelector := routeManager.GetRouteSelector()
	if routeSelector == nil {
		log.Error("could not get route selector")
		return nil
	}

	routesMap := routeManager.GetClientRoutesWithNetID()
	v6Merged := route.V6ExitMergeSet(routesMap)
	resolvedDomains := c.recorder.GetResolvedDomainsStates()

	networkArray := &NetworkArray{
		items: make([]Network, 0),
	}

	for id, routes := range routesMap {
		if len(routes) == 0 {
			continue
		}
		if _, skip := v6Merged[id]; skip {
			continue
		}

		network := c.buildNetwork(id, routes, routeSelector.IsSelected(id), resolvedDomains, v6Merged)
		if network == nil {
			continue
		}
		networkArray.Add(*network)
	}
	return networkArray
}

func (c *Client) buildNetwork(id route.NetID, routes []*route.Route, selected bool, resolvedDomains map[domain.Domain]peer.ResolvedDomainInfo, v6Merged map[route.NetID]struct{}) *Network {
	r := routes[0]
	netStr := r.Network.String()
	if r.IsDynamic() {
		netStr = r.Domains.SafeString()
	}

	routePeer, err := c.findBestRoutePeer(routes)
	if err != nil {
		log.Errorf("could not get peer info for route %s: %v", id, err)
		return nil
	}

	network := &Network{
		Name:       string(id),
		Network:    netStr,
		Peer:       routePeer.FQDN,
		Status:     routePeer.ConnStatus.String(),
		IsSelected: selected,
		Domains:    c.getNetworkDomainsFromRoute(r, resolvedDomains),
	}

	if route.IsV4DefaultRoute(r.Network) && route.HasV6ExitPair(id, v6Merged) {
		network.Network = "0.0.0.0/0, ::/0"
	}

	return network
}

// findBestRoutePeer returns the peer actively routing traffic for the given
// HA route group. Falls back to the first connected peer, then the first peer.
func (c *Client) findBestRoutePeer(routes []*route.Route) (peer.State, error) {
	netStr := routes[0].Network.String()

	fullStatus := c.recorder.GetFullStatus()
	for _, p := range fullStatus.Peers {
		if _, ok := p.GetRoutes()[netStr]; ok {
			return p, nil
		}
	}

	for _, r := range routes {
		p, err := c.recorder.GetPeer(r.Peer)
		if err != nil {
			continue
		}
		if p.ConnStatus == peer.StatusConnected {
			return p, nil
		}
	}
	return c.recorder.GetPeer(routes[0].Peer)
}

// OnUpdatedHostDNS update the DNS servers addresses for root zones
func (c *Client) OnUpdatedHostDNS(list *DNSList) error {
	dnsServer, err := dns.GetServerDns()
	if err != nil {
		return err
	}

	dnsServer.OnUpdatedHostDNSServer(slices.Clone(list.items))
	return nil
}

// SetConnectionListener set the network connection listener
func (c *Client) SetConnectionListener(listener ConnectionListener) {
	c.recorder.SetConnectionListener(connectionListenerAdapter{listener})
}

// RemoveConnectionListener remove connection listener
func (c *Client) RemoveConnectionListener() {
	c.recorder.RemoveConnectionListener()
}

func (c *Client) getRouteManager() (routemanager.Manager, error) {
	client := c.getConnectClient()
	if client == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := client.Engine()
	if engine == nil {
		return nil, fmt.Errorf("engine is not running")
	}

	manager := engine.GetRouteManager()
	if manager == nil {
		return nil, fmt.Errorf("could not get route manager")
	}

	return manager, nil
}

func (c *Client) SelectRoute(id string) error {
	manager, err := c.getRouteManager()
	if err != nil {
		return err
	}

	return manager.SelectRoutes([]route.NetID{route.NetID(id)}, true)
}

func (c *Client) DeselectRoute(id string) error {
	manager, err := c.getRouteManager()
	if err != nil {
		return err
	}

	return manager.DeselectRoutes([]route.NetID{route.NetID(id)})
}

// getNetworkDomainsFromRoute extracts domains from a route and enriches each domain
// with its resolved IP addresses from the provided resolvedDomains map.
func (c *Client) getNetworkDomainsFromRoute(route *route.Route, resolvedDomains map[domain.Domain]peer.ResolvedDomainInfo) NetworkDomains {
	domains := NetworkDomains{}

	for _, d := range route.Domains {
		networkDomain := NetworkDomain{
			Address: d.SafeString(),
		}

		if info, exists := resolvedDomains[d]; exists {
			for _, prefix := range info.Prefixes {
				networkDomain.addResolvedIP(prefix.Addr().String())
			}
		}

		domains.Add(&networkDomain)
	}

	return domains
}

func exportEnvList(list *EnvList) {
	if list == nil {
		return
	}
	for k, v := range list.AllItems() {
		if err := os.Setenv(k, v); err != nil {
			log.Errorf("could not set env variable %s: %v", k, err)
		}
	}
}

// formatDuration renders a duration for display, trimming the fractional part
// to two digits so latencies read as "12.34ms" rather than "12.345678ms".
func formatDuration(d time.Duration) string {
	ds := d.String()
	dotIndex := strings.Index(ds, ".")
	if dotIndex == -1 {
		return ds
	}

	endIndex := min(dotIndex+3, len(ds))

	// Skip the remaining digits so only the unit suffix is appended back.
	unitStart := endIndex
	for unitStart < len(ds) && ds[unitStart] >= '0' && ds[unitStart] <= '9' {
		unitStart++
	}
	return ds[:endIndex] + ds[unitStart:]
}

// formatTime renders a timestamp in UTC using a fixed layout. The zero time is
// passed through as-is so the UI can recognise it and show "never" instead.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}
