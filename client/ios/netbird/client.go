package netbird

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/iface"
)

// ConnectionListener export internal Listener for mobile
type ConnectionListener interface {
	peer.Listener
}

// TunAdapter export internal TunAdapter for mobile
type TunAdapter interface {
	iface.TunAdapter
}

// IFaceDiscover export internal IFaceDiscover for mobile
type IFaceDiscover interface {
	stdnet.ExternalIFaceDiscover
}

// RouteListener export internal RouteListener for mobile
type RouteListener interface {
	routemanager.RouteListener
}

// DnsReadyListener export internal dns ReadyListener for mobile
type DnsReadyListener interface {
	dns.ReadyListener
}

// CustomLogger export internal CustomLogger for mobile
type CustomLogger interface {
	Debug(message string)
	Info(message string)
	Error(message string)
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

// Client struct manage the life circle of background service
type Client struct {
	cfgFile       string
	iFaceDiscover IFaceDiscover
	recorder      *peer.Status
	ctxCancel     context.CancelFunc
	ctxCancelLock *sync.Mutex
	deviceName    string
	routeListener routemanager.RouteListener
	logger        CustomLogger
	onHostDnsFn   func([]string)
}

// NewClient instantiate a new Client
func NewClient(cfgFile, deviceName string, iFaceDiscover IFaceDiscover, routeListener RouteListener, logger CustomLogger) *Client {
	return &Client{
		cfgFile:       cfgFile,
		deviceName:    deviceName,
		iFaceDiscover: iFaceDiscover,
		recorder:      peer.NewRecorder(""),
		ctxCancelLock: &sync.Mutex{},
		logger:        logger,
		routeListener: routeListener,
	}
}

// Run start the internal client. It is a blocker function
// func (c *Client) Run(fd int32, dns *DNSList, dnsReadyListener DnsReadyListener) error {
func (c *Client) Run(fd int32, dns *DNSList, dnsReadyListener DnsReadyListener) error {
	c.logger.Info("Starting NetBird client")
	cfg, err := internal.UpdateOrCreateConfig(internal.ConfigInput{
		ConfigPath: c.cfgFile,
	})
	if err != nil {
		return err
	}
	c.recorder.UpdateManagementAddress(cfg.ManagementURL.String())

	var ctx context.Context
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	c.ctxCancelLock.Lock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)
	defer c.ctxCancel()
	c.ctxCancelLock.Unlock()

	auth := NewAuthWithConfig(ctx, cfg)
	// err = auth.login(urlOpener)
	auth.loginWithSetupKeyAndSaveConfig("E9EEBA50-76A1-4C72-A939-C10655C1CC09", "iPhone")
	if err != nil {
		return err
	}

	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	c.onHostDnsFn = func([]string) {}
	return internal.RunClientiOS(ctx, cfg, c.recorder, fd, c.iFaceDiscover, c.routeListener, dns.items, dnsReadyListener)
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

// ÏSetTraceLogLevel configure the logger to trace level
func (c *Client) SetTraceLogLevel() {
	log.SetLevel(log.TraceLevel)
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
