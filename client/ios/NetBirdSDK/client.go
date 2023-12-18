package NetBirdSDK

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/formatter"
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
	return internal.RunClientiOS(ctx, cfg, c.recorder, fd, c.networkChangeListener, c.dnsManager)
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
		pi := PeerInfo{
			p.IP,
			p.FQDN,
			p.ConnStatus.String(),
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
