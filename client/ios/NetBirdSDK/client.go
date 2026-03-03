//go:build ios

package NetBirdSDK

import (
	"context"
	"fmt"
	"net/netip"
	"os"
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
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
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
	Domains  domain.List
	Selected bool
}

func init() {
	formatter.SetLogcatFormatter(log.StandardLogger())
}

// Client struct manage the life circle of background service
type Client struct {
	cfgFile               string
	stateFile             string
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
	// preloadedConfig holds config loaded from JSON (used on tvOS where file writes are blocked)
	preloadedConfig *profilemanager.Config
}

// NewClient instantiate a new Client
func NewClient(cfgFile, stateFile, deviceName string, osVersion string, osName string, networkChangeListener NetworkChangeListener, dnsManager DnsManager) *Client {
	return &Client{
		cfgFile:               cfgFile,
		stateFile:             stateFile,
		deviceName:            deviceName,
		osName:                osName,
		osVersion:             osVersion,
		recorder:              peer.NewRecorder(""),
		ctxCancelLock:         &sync.Mutex{},
		networkChangeListener: networkChangeListener,
		dnsManager:            dnsManager,
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
	err = auth.LoginSync()
	if err != nil {
		return err
	}

	log.Infof("Auth successful")
	// todo do not throw error in case of cancelled context
	ctx = internal.CtxInitState(ctx)
	c.onHostDnsFn = func([]string) {}
	cfg.WgIface = interfaceName

	c.connectClient = internal.NewConnectClient(ctx, cfg, c.recorder, false)
	return c.connectClient.RunOniOS(fd, c.networkChangeListener, c.dnsManager, c.stateFile)
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
	go func() {
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

	routeManager := engine.GetRouteManager()
	routesMap := routeManager.GetClientRoutesWithNetID()
	if routeManager == nil {
		return nil, fmt.Errorf("could not get route manager")
	}
	routeSelector := routeManager.GetRouteSelector()
	if routeSelector == nil {
		return nil, fmt.Errorf("could not get route selector")
	}

	var routes []*selectRoute
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		route := &selectRoute{
			NetID:    string(id),
			Network:  rt[0].Network,
			Domains:  rt[0].Domains,
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

	resolvedDomains := c.recorder.GetResolvedDomainsStates()

	return prepareRouteSelectionDetails(routes, resolvedDomains), nil

}

func prepareRouteSelectionDetails(routes []*selectRoute, resolvedDomains map[domain.Domain]peer.ResolvedDomainInfo) *RoutesSelectionDetails {
	var routeSelection []RoutesSelectionInfo
	for _, r := range routes {
		domainList := make([]DomainInfo, 0)
		for _, d := range r.Domains {
			domainResp := DomainInfo{
				Domain: d.SafeString(),
			}

			if info, exists := resolvedDomains[d]; exists {
				var ipStrings []string
				for _, prefix := range info.Prefixes {
					ipStrings = append(ipStrings, prefix.Addr().String())
				}
				domainResp.ResolvedIPs = strings.Join(ipStrings, ", ")
			}
			domainList = append(domainList, domainResp)
		}
		domainDetails := DomainDetails{items: domainList}
		routeSelection = append(routeSelection, RoutesSelectionInfo{
			ID:       r.NetID,
			Network:  r.Network.String(),
			Domains:  &domainDetails,
			Selected: r.Selected,
		})
	}

	routeSelectionDetails := RoutesSelectionDetails{items: routeSelection}
	return &routeSelectionDetails
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
		if err := routeSelector.SelectRoutes(routes, true, maps.Keys(routeManager.GetClientRoutesWithNetID())); err != nil {
			log.Debugf("error when selecting routes: %s", err)
			return fmt.Errorf("select routes: %w", err)
		}
	}
	routeManager.TriggerSelection(routeManager.GetClientRoutes())
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
		if err := routeSelector.DeselectRoutes(routes, maps.Keys(routeManager.GetClientRoutesWithNetID())); err != nil {
			log.Debugf("error when deselecting routes: %s", err)
			return fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(routeManager.GetClientRoutes())
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
