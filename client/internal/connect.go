package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/internal/updatemanager"
	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
	nbnet "github.com/netbirdio/netbird/client/net"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ssh"
	sshconfig "github.com/netbirdio/netbird/client/ssh/config"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/auth/hmac"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

type ConnectClient struct {
	ctx                 context.Context
	config              *profilemanager.Config
	statusRecorder      *peer.Status
	doInitialAutoUpdate bool

	engine      *Engine
	engineMutex sync.Mutex

	persistSyncResponse bool
}

func NewConnectClient(
	ctx context.Context,
	config *profilemanager.Config,
	statusRecorder *peer.Status,
	doInitalAutoUpdate bool,
) *ConnectClient {
	return &ConnectClient{
		ctx:                 ctx,
		config:              config,
		statusRecorder:      statusRecorder,
		doInitialAutoUpdate: doInitalAutoUpdate,
		engineMutex:         sync.Mutex{},
	}
}

// Run with main logic.
func (c *ConnectClient) Run(runningChan chan struct{}, logPath string) error {
	return c.run(MobileDependency{}, runningChan, logPath)
}

// RunOnAndroid with main logic on mobile system
func (c *ConnectClient) RunOnAndroid(
	tunAdapter device.TunAdapter,
	iFaceDiscover stdnet.ExternalIFaceDiscover,
	networkChangeListener listener.NetworkChangeListener,
	dnsAddresses []netip.AddrPort,
	dnsReadyListener dns.ReadyListener,
	stateFilePath string,
) error {
	// in case of non Android os these variables will be nil
	mobileDependency := MobileDependency{
		TunAdapter:            tunAdapter,
		IFaceDiscover:         iFaceDiscover,
		NetworkChangeListener: networkChangeListener,
		HostDNSAddresses:      dnsAddresses,
		DnsReadyListener:      dnsReadyListener,
		StateFilePath:         stateFilePath,
	}
	return c.run(mobileDependency, nil, "")
}

func (c *ConnectClient) RunOniOS(
	fileDescriptor int32,
	networkChangeListener listener.NetworkChangeListener,
	dnsManager dns.IosDnsManager,
	stateFilePath string,
) error {
	// Set GC percent to 5% to reduce memory usage as iOS only allows 50MB of memory for the extension.
	debug.SetGCPercent(5)

	mobileDependency := MobileDependency{
		FileDescriptor:        fileDescriptor,
		NetworkChangeListener: networkChangeListener,
		DnsManager:            dnsManager,
		StateFilePath:         stateFilePath,
	}
	return c.run(mobileDependency, nil, "")
}

func (c *ConnectClient) run(mobileDependency MobileDependency, runningChan chan struct{}, logPath string) error {
	defer func() {
		if r := recover(); r != nil {
			rec := c.statusRecorder
			if rec != nil {
				rec.PublishEvent(
					cProto.SystemEvent_CRITICAL, cProto.SystemEvent_SYSTEM,
					"panic occurred",
					"The Netbird service panicked. Please restart the service and submit a bug report with the client logs.",
					nil,
				)
			}

			log.Panicf("Panic occurred: %v, stack trace: %s", r, string(debug.Stack()))
		}
	}()

	log.Infof("starting NetBird client version %s on %s/%s", version.NetbirdVersion(), runtime.GOOS, runtime.GOARCH)

	nbnet.Init()

	backOff := &backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         15 * time.Second,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	state := CtxGetState(c.ctx)
	defer func() {
		s, err := state.Status()
		if err != nil || s != StatusNeedsLogin {
			state.Set(StatusIdle)
		}
	}()

	wrapErr := state.Wrap
	myPrivateKey, err := wgtypes.ParseKey(c.config.PrivateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", c.config.PrivateKey, err.Error())
		return wrapErr(err)
	}

	var mgmTlsEnabled bool
	if c.config.ManagementURL.Scheme == "https" {
		mgmTlsEnabled = true
	}

	publicSSHKey, err := ssh.GeneratePublicKey([]byte(c.config.SSHKey))
	if err != nil {
		return err
	}

	var path string
	if runtime.GOOS == "ios" || runtime.GOOS == "android" {
		// On mobile, use the provided state file path directly
		if !fileExists(mobileDependency.StateFilePath) {
			if err := createFile(mobileDependency.StateFilePath); err != nil {
				log.Errorf("failed to create state file: %v", err)
				// we are not exiting as we can run without the state manager
			}
		}
		path = mobileDependency.StateFilePath
	} else {
		sm := profilemanager.NewServiceManager("")
		path = sm.GetStatePath()
	}
	stateManager := statemanager.New(path)
	stateManager.RegisterState(&sshconfig.ShutdownState{})

	updateManager, err := updatemanager.NewManager(c.statusRecorder, stateManager)
	if err == nil {
		updateManager.CheckUpdateSuccess(c.ctx)

		inst := installer.New()
		if err := inst.CleanUpInstallerFiles(); err != nil {
			log.Errorf("failed to clean up temporary installer file: %v", err)
		}
	}

	defer c.statusRecorder.ClientStop()
	operation := func() error {
		// if context cancelled we not start new backoff cycle
		if c.ctx.Err() != nil {
			return nil
		}

		state.Set(StatusConnecting)

		engineCtx, cancel := context.WithCancel(c.ctx)
		defer func() {
			_, err := state.Status()
			c.statusRecorder.MarkManagementDisconnected(err)
			c.statusRecorder.CleanLocalPeerState()
			cancel()
		}()

		log.Debugf("connecting to the Management service %s", c.config.ManagementURL.Host)
		mgmClient, err := mgm.NewClient(engineCtx, c.config.ManagementURL.Host, myPrivateKey, mgmTlsEnabled)
		if err != nil {
			return wrapErr(gstatus.Errorf(codes.FailedPrecondition, "failed connecting to Management Service : %s", err))
		}
		mgmNotifier := statusRecorderToMgmConnStateNotifier(c.statusRecorder)
		mgmClient.SetConnStateListener(mgmNotifier)

		log.Debugf("connected to the Management service %s", c.config.ManagementURL.Host)
		defer func() {
			if err = mgmClient.Close(); err != nil {
				log.Warnf("failed to close the Management service client %v", err)
			}
		}()

		// connect (just a connection, no stream yet) and login to Management Service to get an initial global Netbird config
		loginResp, err := loginToManagement(engineCtx, mgmClient, publicSSHKey, c.config)
		if err != nil {
			log.Debug(err)
			if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.PermissionDenied) {
				state.Set(StatusNeedsLogin)
				_ = c.Stop()
				return backoff.Permanent(wrapErr(err)) // unrecoverable error
			}
			return wrapErr(err)
		}
		c.statusRecorder.MarkManagementConnected()

		localPeerState := peer.LocalPeerState{
			IP:              loginResp.GetPeerConfig().GetAddress(),
			PubKey:          myPrivateKey.PublicKey().String(),
			KernelInterface: device.WireGuardModuleIsLoaded(),
			FQDN:            loginResp.GetPeerConfig().GetFqdn(),
		}
		c.statusRecorder.UpdateLocalPeerState(localPeerState)

		signalURL := fmt.Sprintf("%s://%s",
			strings.ToLower(loginResp.GetNetbirdConfig().GetSignal().GetProtocol().String()),
			loginResp.GetNetbirdConfig().GetSignal().GetUri(),
		)

		c.statusRecorder.UpdateSignalAddress(signalURL)

		c.statusRecorder.MarkSignalDisconnected(nil)
		defer func() {
			_, err := state.Status()
			c.statusRecorder.MarkSignalDisconnected(err)
		}()

		// with the global Netbird config in hand connect (just a connection, no stream yet) Signal
		signalClient, err := connectToSignal(engineCtx, loginResp.GetNetbirdConfig(), myPrivateKey)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}
		defer func() {
			err = signalClient.Close()
			if err != nil {
				log.Warnf("failed closing Signal service client %v", err)
			}
		}()

		signalNotifier := statusRecorderToSignalConnStateNotifier(c.statusRecorder)
		signalClient.SetConnStateListener(signalNotifier)

		c.statusRecorder.MarkSignalConnected()

		relayURLs, token := parseRelayInfo(loginResp)
		peerConfig := loginResp.GetPeerConfig()

		engineConfig, err := createEngineConfig(myPrivateKey, c.config, peerConfig, logPath)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}

		relayManager := relayClient.NewManager(engineCtx, relayURLs, myPrivateKey.PublicKey().String(), engineConfig.MTU)
		c.statusRecorder.SetRelayMgr(relayManager)
		if len(relayURLs) > 0 {
			if token != nil {
				if err := relayManager.UpdateToken(token); err != nil {
					log.Errorf("failed to update token: %s", err)
					return wrapErr(err)
				}
			}
			log.Infof("connecting to the Relay service(s): %s", strings.Join(relayURLs, ", "))
			if err = relayManager.Serve(); err != nil {
				log.Error(err)
			}
		}

		checks := loginResp.GetChecks()

		c.engineMutex.Lock()
		engine := NewEngine(engineCtx, cancel, signalClient, mgmClient, relayManager, engineConfig, mobileDependency, c.statusRecorder, checks, stateManager)
		engine.SetSyncResponsePersistence(c.persistSyncResponse)
		c.engine = engine
		c.engineMutex.Unlock()

		if err := engine.Start(loginResp.GetNetbirdConfig(), c.config.ManagementURL); err != nil {
			log.Errorf("error while starting Netbird Connection Engine: %s", err)
			return wrapErr(err)
		}

		if loginResp.PeerConfig != nil && loginResp.PeerConfig.AutoUpdate != nil {
			// AutoUpdate will be true when the user click on "Connect" menu on the UI
			if c.doInitialAutoUpdate {
				log.Infof("start engine by ui, run auto-update check")
				c.engine.InitialUpdateHandling(loginResp.PeerConfig.AutoUpdate)
				c.doInitialAutoUpdate = false
			}
		}

		log.Infof("Netbird engine started, the IP is: %s", peerConfig.GetAddress())
		state.Set(StatusConnected)

		if runningChan != nil {
			close(runningChan)
			runningChan = nil
		}

		<-engineCtx.Done()

		c.engineMutex.Lock()
		c.engine = nil
		c.engineMutex.Unlock()

		// todo: consider to remove this condition. Is not thread safe.
		// We should always call Stop(), but we need to verify that it is idempotent
		if engine.wgInterface != nil {
			log.Infof("ensuring %s is removed, Netbird engine context cancelled", engine.wgInterface.Name())

			if err := engine.Stop(); err != nil {
				log.Errorf("Failed to stop engine: %v", err)
			}
		}
		c.statusRecorder.ClientTeardown()

		backOff.Reset()

		log.Info("stopped NetBird client")

		if _, err := state.Status(); errors.Is(err, ErrResetConnection) {
			return err
		}

		return nil
	}

	c.statusRecorder.ClientStart()
	err = backoff.Retry(operation, backOff)
	if err != nil {
		log.Debugf("exiting client retry loop due to unrecoverable error: %s", err)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.PermissionDenied) {
			state.Set(StatusNeedsLogin)
			_ = c.Stop()
		}
		return err
	}
	return nil
}

func parseRelayInfo(loginResp *mgmProto.LoginResponse) ([]string, *hmac.Token) {
	relayCfg := loginResp.GetNetbirdConfig().GetRelay()
	if relayCfg == nil {
		return nil, nil
	}

	token := &hmac.Token{
		Payload:   relayCfg.GetTokenPayload(),
		Signature: relayCfg.GetTokenSignature(),
	}

	return relayCfg.GetUrls(), token
}

func (c *ConnectClient) Engine() *Engine {
	if c == nil {
		return nil
	}
	var e *Engine
	c.engineMutex.Lock()
	e = c.engine
	c.engineMutex.Unlock()
	return e
}

// GetLatestSyncResponse returns the latest sync response from the engine.
func (c *ConnectClient) GetLatestSyncResponse() (*mgmProto.SyncResponse, error) {
	engine := c.Engine()
	if engine == nil {
		return nil, errors.New("engine is not initialized")
	}

	syncResponse, err := engine.GetLatestSyncResponse()
	if err != nil {
		return nil, fmt.Errorf("get latest sync response: %w", err)
	}

	if syncResponse == nil {
		return nil, errors.New("sync response is not available")
	}

	return syncResponse, nil
}

// SetLogLevel sets the log level for the firewall manager if the engine is running.
func (c *ConnectClient) SetLogLevel(level log.Level) {
	engine := c.Engine()
	if engine == nil {
		return
	}

	fwManager := engine.GetFirewallManager()
	if fwManager != nil {
		fwManager.SetLogLevel(level)
	}
}

// Status returns the current client status
func (c *ConnectClient) Status() StatusType {
	if c == nil {
		return StatusIdle
	}
	status, err := CtxGetState(c.ctx).Status()
	if err != nil {
		return StatusIdle
	}

	return status
}

func (c *ConnectClient) Stop() error {
	engine := c.Engine()
	if engine != nil {
		if err := engine.Stop(); err != nil {
			return fmt.Errorf("stop engine: %w", err)
		}
	}
	return nil
}

// SetSyncResponsePersistence enables or disables sync response persistence.
// When enabled, the last received sync response will be stored and can be retrieved
// through the Engine's GetLatestSyncResponse method. When disabled, any stored
// sync response will be cleared.
func (c *ConnectClient) SetSyncResponsePersistence(enabled bool) {
	c.engineMutex.Lock()
	c.persistSyncResponse = enabled
	c.engineMutex.Unlock()

	engine := c.Engine()
	if engine != nil {
		engine.SetSyncResponsePersistence(enabled)
	}
}

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *profilemanager.Config, peerConfig *mgmProto.PeerConfig, logPath string) (*EngineConfig, error) {
	nm := false
	if config.NetworkMonitor != nil {
		nm = *config.NetworkMonitor
	}
	engineConf := &EngineConfig{
		WgIfaceName:                   config.WgIface,
		WgAddr:                        peerConfig.Address,
		IFaceBlackList:                config.IFaceBlackList,
		DisableIPv6Discovery:          config.DisableIPv6Discovery,
		WgPrivateKey:                  key,
		WgPort:                        config.WgPort,
		NetworkMonitor:                nm,
		SSHKey:                        []byte(config.SSHKey),
		NATExternalIPs:                config.NATExternalIPs,
		CustomDNSAddress:              config.CustomDNSAddress,
		RosenpassEnabled:              config.RosenpassEnabled,
		RosenpassPermissive:           config.RosenpassPermissive,
		ServerSSHAllowed:              util.ReturnBoolWithDefaultTrue(config.ServerSSHAllowed),
		EnableSSHRoot:                 config.EnableSSHRoot,
		EnableSSHSFTP:                 config.EnableSSHSFTP,
		EnableSSHLocalPortForwarding:  config.EnableSSHLocalPortForwarding,
		EnableSSHRemotePortForwarding: config.EnableSSHRemotePortForwarding,
		DisableSSHAuth:                config.DisableSSHAuth,
		DNSRouteInterval:              config.DNSRouteInterval,

		DisableClientRoutes: config.DisableClientRoutes,
		DisableServerRoutes: config.DisableServerRoutes || config.BlockInbound,
		DisableDNS:          config.DisableDNS,
		DisableFirewall:     config.DisableFirewall,
		BlockLANAccess:      config.BlockLANAccess,
		BlockInbound:        config.BlockInbound,

		LazyConnectionEnabled: config.LazyConnectionEnabled,

		MTU:     selectMTU(config.MTU, peerConfig.Mtu),
		LogPath: logPath,

		ProfileConfig: config,
	}

	if config.PreSharedKey != "" {
		preSharedKey, err := wgtypes.ParseKey(config.PreSharedKey)
		if err != nil {
			return nil, err
		}
		engineConf.PreSharedKey = &preSharedKey
	}

	port, err := freePort(config.WgPort)
	if err != nil {
		return nil, err
	}
	if port != config.WgPort {
		log.Infof("using %d as wireguard port: %d is in use", port, config.WgPort)
	}
	engineConf.WgPort = port

	return engineConf, nil
}

func selectMTU(localMTU uint16, peerMTU int32) uint16 {
	var finalMTU uint16 = iface.DefaultMTU
	if localMTU > 0 {
		finalMTU = localMTU
	} else if peerMTU > 0 {
		finalMTU = uint16(peerMTU)
	}

	// Set global DNS MTU
	dns.SetCurrentMTU(finalMTU)

	return finalMTU
}

// connectToSignal creates Signal Service client and established a connection
func connectToSignal(ctx context.Context, wtConfig *mgmProto.NetbirdConfig, ourPrivateKey wgtypes.Key) (*signal.GrpcClient, error) {
	var sigTLSEnabled bool
	if wtConfig.Signal.Protocol == mgmProto.HostConfig_HTTPS {
		sigTLSEnabled = true
	} else {
		sigTLSEnabled = false
	}

	signalClient, err := signal.NewClient(ctx, wtConfig.Signal.Uri, ourPrivateKey, sigTLSEnabled)
	if err != nil {
		log.Errorf("error while connecting to the Signal Exchange Service %s: %s", wtConfig.Signal.Uri, err)
		return nil, gstatus.Errorf(codes.FailedPrecondition, "failed connecting to Signal Service : %s", err)
	}

	return signalClient, nil
}

// loginToManagement creates Management ServiceDependencies client, establishes a connection, logs-in and gets a global Netbird config (signal, turn, stun hosts, etc)
func loginToManagement(ctx context.Context, client mgm.Client, pubSSHKey []byte, config *profilemanager.Config) (*mgmProto.LoginResponse, error) {

	serverPublicKey, err := client.GetServerPublicKey()
	if err != nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "failed while getting Management Service public key: %s", err)
	}

	sysInfo := system.GetInfo(ctx)
	sysInfo.SetFlags(
		config.RosenpassEnabled,
		config.RosenpassPermissive,
		config.ServerSSHAllowed,
		config.DisableClientRoutes,
		config.DisableServerRoutes,
		config.DisableDNS,
		config.DisableFirewall,
		config.BlockLANAccess,
		config.BlockInbound,
		config.LazyConnectionEnabled,
		config.EnableSSHRoot,
		config.EnableSSHSFTP,
		config.EnableSSHLocalPortForwarding,
		config.EnableSSHRemotePortForwarding,
		config.DisableSSHAuth,
	)
	loginResp, err := client.Login(*serverPublicKey, sysInfo, pubSSHKey, config.DNSLabels)
	if err != nil {
		return nil, err
	}

	return loginResp, nil
}

func statusRecorderToMgmConnStateNotifier(statusRecorder *peer.Status) mgm.ConnStateNotifier {
	var sri interface{} = statusRecorder
	mgmNotifier, _ := sri.(mgm.ConnStateNotifier)
	return mgmNotifier
}

func statusRecorderToSignalConnStateNotifier(statusRecorder *peer.Status) signal.ConnStateNotifier {
	var sri interface{} = statusRecorder
	notifier, _ := sri.(signal.ConnStateNotifier)
	return notifier
}

// freePort attempts to determine if the provided port is available, if not it will ask the system for a free port.
func freePort(initPort int) (int, error) {
	addr := net.UDPAddr{Port: initPort}

	conn, err := net.ListenUDP("udp", &addr)
	if err == nil {
		returnPort := conn.LocalAddr().(*net.UDPAddr).Port
		closeConnWithLog(conn)
		return returnPort, nil
	}

	// if the port is already in use, ask the system for a free port
	addr.Port = 0
	conn, err = net.ListenUDP("udp", &addr)
	if err != nil {
		return 0, fmt.Errorf("unable to get a free port: %v", err)
	}

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, errors.New("wrong address type when getting a free port")
	}
	closeConnWithLog(conn)
	return udpAddr.Port, nil
}

func closeConnWithLog(conn *net.UDPConn) {
	startClosing := time.Now()
	err := conn.Close()
	if err != nil {
		log.Warnf("closing probe port %d failed: %v. NetBird will still attempt to use this port for connection.", conn.LocalAddr().(*net.UDPAddr).Port, err)
	}
	if time.Since(startClosing) > time.Second {
		log.Warnf("closing the testing port %d took %s. Usually it is safe to ignore, but continuous warnings may indicate a problem.", conn.LocalAddr().(*net.UDPAddr).Port, time.Since(startClosing))
	}
}
