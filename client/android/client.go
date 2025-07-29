//go:build android

package android

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/client/net"
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
	cfgFile               string
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
func NewClient(cfgFile string, androidSDKVersion int, deviceName string, uiVersion string, tunAdapter TunAdapter, iFaceDiscover IFaceDiscover, networkChangeListener NetworkChangeListener) *Client {
	execWorkaround(androidSDKVersion)

	net.SetAndroidProtectSocketFn(tunAdapter.ProtectSocket)
	return &Client{
		cfgFile:               cfgFile,
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
func (c *Client) Run(urlOpener URLOpener, dns *DNSList, dnsReadyListener DnsReadyListener) error {
	cfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath: c.cfgFile,
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
	err = auth.login(urlOpener)
	if err != nil {
		return err
	}

	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	c.connectClient = internal.NewConnectClient(ctx, cfg, c.recorder)
	return c.connectClient.RunOnAndroid(c.tunAdapter, c.iFaceDiscover, c.networkChangeListener, dns.items, dnsReadyListener)
}

// RunWithoutLogin we apply this type of run function when the backed has been started without UI (i.e. after reboot).
// In this case make no sense handle registration steps.
func (c *Client) RunWithoutLogin(dns *DNSList, dnsReadyListener DnsReadyListener) error {
	cfg, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath: c.cfgFile,
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
	c.connectClient = internal.NewConnectClient(ctx, cfg, c.recorder)
	return c.connectClient.RunOnAndroid(c.tunAdapter, c.iFaceDiscover, c.networkChangeListener, dns.items, dnsReadyListener)
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

	networkArray := &NetworkArray{
		items: make([]Network, 0),
	}

	for id, routes := range routeManager.GetClientRoutesWithNetID() {
		if len(routes) == 0 {
			continue
		}

		r := routes[0]
		netStr := r.Network.String()
		if r.IsDynamic() {
			netStr = r.Domains.SafeString()
		}

		peer, err := c.recorder.GetPeer(routes[0].Peer)
		if err != nil {
			log.Errorf("could not get peer info for %s: %v", routes[0].Peer, err)
			continue
		}
		network := Network{
			Name:    string(id),
			Network: netStr,
			Peer:    peer.FQDN,
			Status:  peer.ConnStatus.String(),
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

	dnsServer.OnUpdatedHostDNSServer(list.items)
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
