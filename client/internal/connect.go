package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/iface"
	mgm "github.com/netbirdio/netbird/management/client"
	mgmProto "github.com/netbirdio/netbird/management/proto"
	signal "github.com/netbirdio/netbird/signal/client"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

type ConnectClient struct {
	ctx            context.Context
	config         *Config
	statusRecorder *peer.Status
	engine         *Engine
	engineMutex    sync.Mutex
}

func NewConnectClient(
	ctx context.Context,
	config *Config,
	statusRecorder *peer.Status,

) *ConnectClient {
	return &ConnectClient{
		ctx:            ctx,
		config:         config,
		statusRecorder: statusRecorder,
		engineMutex:    sync.Mutex{},
	}
}

// Run with main logic.
func (c *ConnectClient) Run() error {
	return c.run(MobileDependency{}, nil, nil, nil, nil)
}

// RunWithProbes runs the client's main logic with probes attached
func (c *ConnectClient) RunWithProbes(
	mgmProbe *Probe,
	signalProbe *Probe,
	relayProbe *Probe,
	wgProbe *Probe,
) error {
	return c.run(MobileDependency{}, mgmProbe, signalProbe, relayProbe, wgProbe)
}

// RunOnAndroid with main logic on mobile system
func (c *ConnectClient) RunOnAndroid(
	tunAdapter iface.TunAdapter,
	iFaceDiscover stdnet.ExternalIFaceDiscover,
	networkChangeListener listener.NetworkChangeListener,
	dnsAddresses []string,
	dnsReadyListener dns.ReadyListener,
) error {
	// in case of non Android os these variables will be nil
	mobileDependency := MobileDependency{
		TunAdapter:            tunAdapter,
		IFaceDiscover:         iFaceDiscover,
		NetworkChangeListener: networkChangeListener,
		HostDNSAddresses:      dnsAddresses,
		DnsReadyListener:      dnsReadyListener,
	}
	return c.run(mobileDependency, nil, nil, nil, nil)
}

func (c *ConnectClient) RunOniOS(
	fileDescriptor int32,
	networkChangeListener listener.NetworkChangeListener,
	dnsManager dns.IosDnsManager,
) error {
	// Set GC percent to 5% to reduce memory usage as iOS only allows 50MB of memory for the extension.
	debug.SetGCPercent(5)

	mobileDependency := MobileDependency{
		FileDescriptor:        fileDescriptor,
		NetworkChangeListener: networkChangeListener,
		DnsManager:            dnsManager,
	}
	return c.run(mobileDependency, nil, nil, nil, nil)
}

func (c *ConnectClient) run(
	mobileDependency MobileDependency,
	mgmProbe *Probe,
	signalProbe *Probe,
	relayProbe *Probe,
	wgProbe *Probe,
) error {
	defer func() {
		if r := recover(); r != nil {
			log.Panicf("Panic occurred: %v, stack trace: %s", r, string(debug.Stack()))
		}
	}()

	log.Infof("starting NetBird client version %s on %s/%s", version.NetbirdVersion(), runtime.GOOS, runtime.GOARCH)

	// Check if client was not shut down in a clean way and restore DNS config if required.
	// Otherwise, we might not be able to connect to the management server to retrieve new config.
	if err := dns.CheckUncleanShutdown(c.config.WgIface); err != nil {
		log.Errorf("checking unclean shutdown error: %s", err)
	}

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

	defer c.statusRecorder.ClientStop()
	operation := func() error {
		// if context cancelled we not start new backoff cycle
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		state.Set(StatusConnecting)

		engineCtx, cancel := context.WithCancel(c.ctx)
		defer func() {
			c.statusRecorder.MarkManagementDisconnected(state.err)
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
			err = mgmClient.Close()
			if err != nil {
				log.Warnf("failed to close the Management service client %v", err)
			}
		}()

		// connect (just a connection, no stream yet) and login to Management Service to get an initial global Wiretrustee config
		loginResp, err := loginToManagement(engineCtx, mgmClient, publicSSHKey)
		if err != nil {
			log.Debug(err)
			if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.PermissionDenied) {
				state.Set(StatusNeedsLogin)
				return backoff.Permanent(wrapErr(err)) // unrecoverable error
			}
			return wrapErr(err)
		}
		c.statusRecorder.MarkManagementConnected()

		localPeerState := peer.LocalPeerState{
			IP:              loginResp.GetPeerConfig().GetAddress(),
			PubKey:          myPrivateKey.PublicKey().String(),
			KernelInterface: iface.WireGuardModuleIsLoaded(),
			FQDN:            loginResp.GetPeerConfig().GetFqdn(),
		}

		c.statusRecorder.UpdateLocalPeerState(localPeerState)

		signalURL := fmt.Sprintf("%s://%s",
			strings.ToLower(loginResp.GetWiretrusteeConfig().GetSignal().GetProtocol().String()),
			loginResp.GetWiretrusteeConfig().GetSignal().GetUri(),
		)

		c.statusRecorder.UpdateSignalAddress(signalURL)

		c.statusRecorder.MarkSignalDisconnected(nil)
		defer func() {
			c.statusRecorder.MarkSignalDisconnected(state.err)
		}()

		// with the global Wiretrustee config in hand connect (just a connection, no stream yet) Signal
		signalClient, err := connectToSignal(engineCtx, loginResp.GetWiretrusteeConfig(), myPrivateKey)
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

		peerConfig := loginResp.GetPeerConfig()

		engineConfig, err := createEngineConfig(myPrivateKey, c.config, peerConfig)
		if err != nil {
			log.Error(err)
			return wrapErr(err)
		}

		c.engineMutex.Lock()
		c.engine = NewEngineWithProbes(engineCtx, cancel, signalClient, mgmClient, engineConfig, mobileDependency, c.statusRecorder, mgmProbe, signalProbe, relayProbe, wgProbe)
		c.engineMutex.Unlock()

		err = c.engine.Start()
		if err != nil {
			log.Errorf("error while starting Netbird Connection Engine: %s", err)
			return wrapErr(err)
		}

		log.Infof("Netbird engine started, the IP is: %s", peerConfig.GetAddress())
		state.Set(StatusConnected)

		<-engineCtx.Done()
		c.statusRecorder.ClientTeardown()

		backOff.Reset()

		err = c.engine.Stop()
		if err != nil {
			log.Errorf("failed stopping engine %v", err)
			return wrapErr(err)
		}

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
		}
		return err
	}
	return nil
}

func (c *ConnectClient) Engine() *Engine {
	var e *Engine
	c.engineMutex.Lock()
	e = c.engine
	c.engineMutex.Unlock()
	return e
}

// createEngineConfig converts configuration received from Management Service to EngineConfig
func createEngineConfig(key wgtypes.Key, config *Config, peerConfig *mgmProto.PeerConfig) (*EngineConfig, error) {
	engineConf := &EngineConfig{
		WgIfaceName:          config.WgIface,
		WgAddr:               peerConfig.Address,
		WgAddr6:              peerConfig.Address6,
		IFaceBlackList:       config.IFaceBlackList,
		DisableIPv6Discovery: config.DisableIPv6Discovery,
		WgPrivateKey:         key,
		WgPort:               config.WgPort,
		NetworkMonitor:       config.NetworkMonitor,
		SSHKey:               []byte(config.SSHKey),
		NATExternalIPs:       config.NATExternalIPs,
		CustomDNSAddress:     config.CustomDNSAddress,
		RosenpassEnabled:     config.RosenpassEnabled,
		RosenpassPermissive:  config.RosenpassPermissive,
		ServerSSHAllowed:     util.ReturnBoolWithDefaultTrue(config.ServerSSHAllowed),
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

// connectToSignal creates Signal Service client and established a connection
func connectToSignal(ctx context.Context, wtConfig *mgmProto.WiretrusteeConfig, ourPrivateKey wgtypes.Key) (*signal.GrpcClient, error) {
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

// loginToManagement creates Management Services client, establishes a connection, logs-in and gets a global Wiretrustee config (signal, turn, stun hosts, etc)
func loginToManagement(ctx context.Context, client mgm.Client, pubSSHKey []byte) (*mgmProto.LoginResponse, error) {

	serverPublicKey, err := client.GetServerPublicKey()
	if err != nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "failed while getting Management Service public key: %s", err)
	}

	sysInfo := system.GetInfo(ctx)
	loginResp, err := client.Login(*serverPublicKey, sysInfo, pubSSHKey)
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

func freePort(start int) (int, error) {
	addr := net.UDPAddr{}
	if start == 0 {
		start = iface.DefaultWgPort
	}
	for x := start; x <= 65535; x++ {
		addr.Port = x
		conn, err := net.ListenUDP("udp", &addr)
		if err != nil {
			continue
		}
		conn.Close()
		return x, nil
	}
	return 0, errors.New("no free ports")
}
