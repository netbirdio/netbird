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
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	types "github.com/netbirdio/netbird/upload-server/types"
)

// ConnectionListener export internal Listener for mobile
type ConnectionListener interface {
	peer.Listener
}

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

	stateMu       sync.RWMutex
	connectClient *internal.ConnectClient
	config        *profilemanager.Config
	cacheDir      string
}

func (c *Client) setState(cfg *profilemanager.Config, cacheDir string, cc *internal.ConnectClient) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.config = cfg
	c.cacheDir = cacheDir
	c.connectClient = cc
}

func (c *Client) stateSnapshot() (*profilemanager.Config, string, *internal.ConnectClient) {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.config, c.cacheDir, c.connectClient
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
	}
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

	auth := NewAuthWithConfig(ctx, cfg)
	err = auth.login(urlOpener, isAndroidTV)
	if err != nil {
		return err
	}

	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	connectClient := internal.NewConnectClient(ctx, cfg, c.recorder)
	c.setState(cfg, cacheDir, connectClient)
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
	connectClient := internal.NewConnectClient(ctx, cfg, c.recorder)
	c.setState(cfg, cacheDir, connectClient)
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

	key, err := debug.UploadDebugBundle(uploadCtx, types.DefaultBundleURL, cfg.ManagementURL.String(), path)
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
	// Refresh WireGuard counters (BytesRx/Tx + LastWireguardHandshake)
	// from the kernel/uapi interface before snapshotting. Without this
	// the Android UI sees the stale values that were last written when
	// the peer was opened/closed (typically 0), because the desktop
	// CLI's Status RPC is what normally drives RefreshWireGuardStats.
	// Phase 3.7i.
	if err := c.recorder.RefreshWireGuardStats(); err != nil {
		log.Debugf("PeersList: refresh wg stats: %v", err)
	}

	fullStatus := c.recorder.GetFullStatus()

	peerInfos := make([]PeerInfo, len(fullStatus.Peers))
	for n, p := range fullStatus.Peers {
		pi := PeerInfo{
			IP:         p.IP,
			FQDN:       p.FQDN,
			ConnStatus: int(p.ConnStatus),
			Routes:     PeerRoutes{routes: maps.Keys(p.GetRoutes())},
		}

		// Phase 3.7i (#5989): enrichment fields.
		pi.Relayed = p.Relayed
		pi.ServerOnline = p.ServerOnline
		pi.LocalIceCandidateEndpoint = p.LocalIceCandidateEndpoint
		pi.RemoteIceCandidateEndpoint = p.RemoteIceCandidateEndpoint
		pi.RelayServerAddress = p.RelayServerAddress
		if !p.LastWireguardHandshake.IsZero() {
			pi.LastWireguardHandshake = p.LastWireguardHandshake.Format(time.RFC3339)
		}
		if !p.RemoteLastSeenAtServer.IsZero() {
			pi.LastSeenAtServer = p.RemoteLastSeenAtServer.Format(time.RFC3339)
		}
		pi.LatencyMs = p.Latency.Milliseconds()
		pi.BytesRx = p.BytesRx
		pi.BytesTx = p.BytesTx
		pi.EffectiveConnectionMode = p.RemoteEffectiveConnectionMode
		pi.ConfiguredConnectionMode = p.RemoteConfiguredConnectionMode
		if len(p.RemoteGroups) > 0 {
			pi.Groups = strings.Join(p.RemoteGroups, ",")
		}
		// AgentVersion / OsVersion: peer.State does not expose these fields;
		// left empty until daemon surfaces them (future phase).

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

	networkArray := &NetworkArray{
		items: make([]Network, 0),
	}

	resolvedDomains := c.recorder.GetResolvedDomainsStates()

	for id, routes := range routeManager.GetClientRoutesWithNetID() {
		if len(routes) == 0 {
			continue
		}

		r := routes[0]
		domains := c.getNetworkDomainsFromRoute(r, resolvedDomains)
		netStr := r.Network.String()

		if r.IsDynamic() {
			netStr = r.Domains.SafeString()
		}

		routePeer, err := c.recorder.GetPeer(routes[0].Peer)
		if err != nil {
			log.Errorf("could not get peer info for %s: %v", routes[0].Peer, err)
			continue
		}
		network := Network{
			Name:       string(id),
			Network:    netStr,
			Peer:       routePeer.FQDN,
			Status:     routePeer.ConnStatus.String(),
			IsSelected: routeSelector.IsSelected(id),
			Domains:    domains,
		}
		networkArray.Add(network)
	}
	return networkArray
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
	c.recorder.SetConnectionListener(listener)
}

// RemoveConnectionListener remove connection listener
func (c *Client) RemoveConnectionListener() {
	c.recorder.RemoveConnectionListener()
}

// GetServerPushedConnectionMode returns the canonical name of the
// connection mode the management server most recently pushed via
// PeerConfig (independent of any local profile/env override). Returns
// an empty string when the engine has not connected yet or the server
// has not pushed a value -- the Android UI then knows to display
// just "Follow server" without the (currently: ...) suffix.
func (c *Client) GetServerPushedConnectionMode() string {
	cm := c.connMgrSafe()
	if cm == nil {
		return ""
	}
	return cm.ServerPushedMode().String()
}

// GetServerPushedRelayTimeoutSecs returns the relay timeout in seconds
// most recently pushed by the management server, or 0 when no value
// has been received. Used by the Android UI as a hint.
func (c *Client) GetServerPushedRelayTimeoutSecs() int64 {
	cm := c.connMgrSafe()
	if cm == nil {
		return 0
	}
	return int64(cm.ServerPushedRelayTimeoutSecs())
}

// GetServerPushedP2pTimeoutSecs returns the ICE-only timeout (seconds)
// most recently pushed by the management server.
func (c *Client) GetServerPushedP2pTimeoutSecs() int64 {
	cm := c.connMgrSafe()
	if cm == nil {
		return 0
	}
	return int64(cm.ServerPushedP2pTimeoutSecs())
}

// GetServerPushedP2pRetryMaxSecs returns the ICE-backoff cap (seconds)
// most recently pushed by the management server.
func (c *Client) GetServerPushedP2pRetryMaxSecs() int64 {
	cm := c.connMgrSafe()
	if cm == nil {
		return 0
	}
	return int64(cm.ServerPushedP2pRetryMaxSecs())
}

// GetConfiguredPeersTotal returns the total number of configured peers
// (server-online + server-offline). Phase 3.7i (#5989).
func (c *Client) GetConfiguredPeersTotal() int64 {
	return int64(c.recorder.GetFullStatus().ConfiguredPeersTotal)
}

// GetServerOnlinePeers returns the number of peers that are reachable via
// the server (P2P + Relayed + Idle). Phase 3.7i (#5989).
func (c *Client) GetServerOnlinePeers() int64 {
	return int64(c.recorder.GetFullStatus().ServerOnlinePeers)
}

// GetP2PConnectedPeers returns the number of peers connected via direct
// P2P (ICE). Phase 3.7i (#5989).
func (c *Client) GetP2PConnectedPeers() int64 {
	return int64(c.recorder.GetFullStatus().P2PConnectedPeers)
}

// GetRelayedConnectedPeers returns the number of peers connected via relay.
// Phase 3.7i (#5989).
func (c *Client) GetRelayedConnectedPeers() int64 {
	return int64(c.recorder.GetFullStatus().RelayedConnectedPeers)
}

// GetIdleOnlinePeers returns the number of peers that are online on the
// server but have no active connection yet. Phase 3.7i (#5989).
func (c *Client) GetIdleOnlinePeers() int64 {
	return int64(c.recorder.GetFullStatus().IdleOnlinePeers)
}

// GetServerOfflinePeers returns the number of peers that are not reachable
// via the server. Phase 3.7i (#5989).
func (c *Client) GetServerOfflinePeers() int64 {
	return int64(c.recorder.GetFullStatus().ServerOfflinePeers)
}

// connMgrSafe is a small helper that walks the Client -> ConnectClient
// -> Engine -> ConnMgr chain and returns nil at the first nil pointer.
// Each accessor that surfaces engine state to the Android UI uses it.
func (c *Client) connMgrSafe() *internal.ConnMgr {
	cc := c.getConnectClient()
	if cc == nil {
		return nil
	}
	engine := cc.Engine()
	if engine == nil {
		return nil
	}
	return engine.ConnMgr()
}

func (c *Client) toggleRoute(command routeCommand) error {
	return command.toggleRoute()
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

func (c *Client) SelectRoute(route string) error {
	manager, err := c.getRouteManager()
	if err != nil {
		return err
	}

	return c.toggleRoute(selectRouteCommand{route: route, manager: manager})
}

func (c *Client) DeselectRoute(route string) error {
	manager, err := c.getRouteManager()
	if err != nil {
		return err
	}

	return c.toggleRoute(deselectRouteCommand{route: route, manager: manager})
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
