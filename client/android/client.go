//go:build android

package android

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"

	"golang.org/x/exp/maps"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal"
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

	connectClient *internal.ConnectClient
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
	c.connectClient = internal.NewConnectClient(ctx, cfg, c.recorder, false)
	return c.connectClient.RunOnAndroid(c.tunAdapter, c.iFaceDiscover, c.networkChangeListener, slices.Clone(dns.items), dnsReadyListener, stateFile)
}

// RunWithoutLogin we apply this type of run function when the backed has been started without UI (i.e. after reboot).
// In this case make no sense handle registration steps.
func (c *Client) RunWithoutLogin(platformFiles PlatformFiles, dns *DNSList, dnsReadyListener DnsReadyListener, envList *EnvList) error {
	exportEnvList(envList)

	cfgFile := platformFiles.ConfigurationFilePath()
	stateFile := platformFiles.StateFilePath()

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
	c.connectClient = internal.NewConnectClient(ctx, cfg, c.recorder, false)
	return c.connectClient.RunOnAndroid(c.tunAdapter, c.iFaceDiscover, c.networkChangeListener, slices.Clone(dns.items), dnsReadyListener, stateFile)
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
	if c.connectClient == nil {
		return fmt.Errorf("engine not running")
	}

	e := c.connectClient.Engine()
	if e == nil {
		return fmt.Errorf("engine not initialized")
	}

	return e.RenewTun(fd)
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

	fullStatus := c.recorder.GetFullStatus()

	peerInfos := make([]PeerInfo, len(fullStatus.Peers))
	for n, p := range fullStatus.Peers {
		pi := PeerInfo{
			p.IP,
			p.FQDN,
			p.ConnStatus.String(),
			PeerRoutes{routes: maps.Keys(p.GetRoutes())},
		}
		peerInfos[n] = pi
	}
	return &PeerInfoArray{items: peerInfos}
}

func (c *Client) Networks() *NetworkArray {
	if c.connectClient == nil {
		log.Error("not connected")
		return nil
	}

	engine := c.connectClient.Engine()
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

func (c *Client) toggleRoute(command routeCommand) error {
	return command.toggleRoute()
}

func (c *Client) getRouteManager() (routemanager.Manager, error) {
	client := c.connectClient
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
