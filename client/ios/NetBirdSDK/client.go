package NetBirdSDK

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/route"
)

// ConnectionListener export internal Listener for mobile
type ConnectionListener interface {
	peer.Listener
}

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
	NetID    string
	Network  netip.Prefix
	Selected bool
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

// Client struct manage the life circle of background service
type Client struct {
	cfgFile               string
	recorder              *peer.Status
	ctxCancel             context.CancelFunc
	ctxCancelLock         *sync.Mutex
	deviceName            string
	osName                string
	osVersion             string
	networkChangeListener listener.NetworkChangeListener
	onHostDnsFn           func([]string)
	dnsManager            dns.IosDnsManager
	loginComplete         bool
	connectClient         *internal.ConnectClient
}

// NewClient instantiate a new Client
func NewClient(cfgFile, deviceName string, osVersion string, osName string, networkChangeListener NetworkChangeListener, dnsManager DnsManager) *Client {
	return &Client{
		cfgFile:               cfgFile,
		deviceName:            deviceName,
		osName:                osName,
		osVersion:             osVersion,
		recorder:              peer.NewRecorder(""),
		ctxCancelLock:         &sync.Mutex{},
		networkChangeListener: networkChangeListener,
		dnsManager:            dnsManager,
	}
}

// Run start the internal client. It is a blocker function
func (c *Client) Run(fd int32, interfaceName string) error {
	log.Infof("Starting NetBird client")
	log.Debugf("Tunnel uses interface: %s", interfaceName)
	cfg, err := internal.UpdateOrCreateConfig(internal.ConfigInput{
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
	ctxWithValues = context.WithValue(ctxWithValues, system.OsNameCtxKey, c.osName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsVersionCtxKey, c.osVersion)
	c.ctxCancelLock.Lock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)
	defer c.ctxCancel()
	c.ctxCancelLock.Unlock()

	auth := NewAuthWithConfig(ctx, cfg)
	err = auth.Login()
	if err != nil {
		return err
	}

	log.Infof("Auth successful")
	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	c.onHostDnsFn = func([]string) {}
	cfg.WgIface = interfaceName

	c.connectClient = internal.NewConnectClient(ctx, cfg, c.recorder)
	return c.connectClient.RunOniOS(fd, c.networkChangeListener, c.dnsManager)
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

// getStatusDetails return with the list of the PeerInfos
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
			Direct:                     p.Direct,
			LastWireguardHandshake:     p.LastWireguardHandshake.String(),
			Relayed:                    p.Relayed,
			RosenpassEnabled:           p.RosenpassEnabled,
			Routes:                     routes,
		}
		peerInfos[n] = pi
	}
	return &StatusDetails{items: peerInfos, fqdn: fullStatus.LocalPeerState.FQDN, ip: fullStatus.LocalPeerState.IP}
}

// SetConnectionListener set the network connection listener
func (c *Client) SetConnectionListener(listener ConnectionListener) {
	c.recorder.SetConnectionListener(listener)
}

// RemoveConnectionListener remove connection listener
func (c *Client) RemoveConnectionListener() {
	c.recorder.RemoveConnectionListener()
}

func (c *Client) IsLoginRequired() bool {
	var ctx context.Context
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsNameCtxKey, c.osName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsVersionCtxKey, c.osVersion)
	c.ctxCancelLock.Lock()
	defer c.ctxCancelLock.Unlock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)

	cfg, _ := internal.UpdateOrCreateConfig(internal.ConfigInput{
		ConfigPath: c.cfgFile,
	})

	needsLogin, _ := internal.IsLoginRequired(ctx, cfg.PrivateKey, cfg.ManagementURL, cfg.SSHKey)
	return needsLogin
}

func (c *Client) LoginForMobile() string {
	var ctx context.Context
	//nolint
	ctxWithValues := context.WithValue(context.Background(), system.DeviceNameCtxKey, c.deviceName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsNameCtxKey, c.osName)
	//nolint
	ctxWithValues = context.WithValue(ctxWithValues, system.OsVersionCtxKey, c.osVersion)
	c.ctxCancelLock.Lock()
	defer c.ctxCancelLock.Unlock()
	ctx, c.ctxCancel = context.WithCancel(ctxWithValues)

	cfg, _ := internal.UpdateOrCreateConfig(internal.ConfigInput{
		ConfigPath: c.cfgFile,
	})

	oAuthFlow, err := auth.NewOAuthFlow(ctx, cfg, false)
	if err != nil {
		return err.Error()
	}

	flowInfo, err := oAuthFlow.RequestAuthInfo(context.TODO())
	if err != nil {
		return err.Error()
	}

	// This could cause a potential race condition with loading the extension which need to be handled on swift side
	go func() {
		waitTimeout := time.Duration(flowInfo.ExpiresIn) * time.Second
		waitCTX, cancel := context.WithTimeout(ctx, waitTimeout)
		defer cancel()
		tokenInfo, err := oAuthFlow.WaitToken(waitCTX, flowInfo)
		if err != nil {
			return
		}
		jwtToken := tokenInfo.GetTokenToUse()
		_ = internal.Login(ctx, cfg, "", jwtToken)
		c.loginComplete = true
	}()

	return flowInfo.VerificationURIComplete
}

func (c *Client) IsLoginComplete() bool {
	return c.loginComplete
}

func (c *Client) ClearLoginComplete() {
	c.loginComplete = false
}

func (c *Client) GetRoutesSelectionDetails() (*RoutesSelectionDetails, error) {
	if c.connectClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := c.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routesMap := engine.GetClientRoutesWithNetID()
	routeSelector := engine.GetRouteManager().GetRouteSelector()

	var routes []*selectRoute
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		route := &selectRoute{
			NetID:    string(id),
			Network:  rt[0].Network,
			Selected: routeSelector.IsSelected(id),
		}
		routes = append(routes, route)
	}

	sort.Slice(routes, func(i, j int) bool {
		iPrefix := routes[i].Network.Bits()
		jPrefix := routes[j].Network.Bits()

		if iPrefix == jPrefix {
			iAddr := routes[i].Network.Addr()
			jAddr := routes[j].Network.Addr()
			if iAddr == jAddr {
				return routes[i].NetID < routes[j].NetID
			}
			return iAddr.String() < jAddr.String()
		}
		return iPrefix < jPrefix
	})

	var routeSelection []RoutesSelectionInfo
	for _, r := range routes {
		routeSelection = append(routeSelection, RoutesSelectionInfo{
			ID:       r.NetID,
			Network:  r.Network.String(),
			Selected: r.Selected,
		})
	}

	routeSelectionDetails := RoutesSelectionDetails{items: routeSelection}
	return &routeSelectionDetails, nil
}

func (c *Client) SelectRoute(id string) error {
	if c.connectClient == nil {
		return fmt.Errorf("not connected")
	}

	engine := c.connectClient.Engine()
	if engine == nil {
		return fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	routeSelector := routeManager.GetRouteSelector()
	if id == "All" {
		log.Debugf("select all routes")
		routeSelector.SelectAllRoutes()
	} else {
		log.Debugf("select route with id: %s", id)
		routes := toNetIDs([]string{id})
		if err := routeSelector.SelectRoutes(routes, true, maps.Keys(engine.GetClientRoutesWithNetID())); err != nil {
			log.Debugf("error when selecting routes: %s", err)
			return fmt.Errorf("select routes: %w", err)
		}
	}
	routeManager.TriggerSelection(engine.GetClientRoutes())
	return nil

}

func (c *Client) DeselectRoute(id string) error {
	if c.connectClient == nil {
		return fmt.Errorf("not connected")
	}
	engine := c.connectClient.Engine()
	if engine == nil {
		return fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	routeSelector := routeManager.GetRouteSelector()
	if id == "All" {
		log.Debugf("deselect all routes")
		routeSelector.DeselectAllRoutes()
	} else {
		log.Debugf("deselect route with id: %s", id)
		routes := toNetIDs([]string{id})
		if err := routeSelector.DeselectRoutes(routes, maps.Keys(engine.GetClientRoutesWithNetID())); err != nil {
			log.Debugf("error when deselecting routes: %s", err)
			return fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(engine.GetClientRoutes())
	return nil
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
