package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/exp/maps"

	"google.golang.org/protobuf/types/known/durationpb"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/system"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

const (
	probeThreshold          = time.Second * 5
	retryInitialIntervalVar = "NB_CONN_RETRY_INTERVAL_TIME"
	maxRetryIntervalVar     = "NB_CONN_MAX_RETRY_INTERVAL_TIME"
	maxRetryTimeVar         = "NB_CONN_MAX_RETRY_TIME_TIME"
	retryMultiplierVar      = "NB_CONN_RETRY_MULTIPLIER"
	defaultInitialRetryTime = 30 * time.Minute
	defaultMaxRetryInterval = 60 * time.Minute
	defaultMaxRetryTime     = 14 * 24 * time.Hour
	defaultRetryMultiplier  = 1.7
)

// Server for service control.
type Server struct {
	rootCtx   context.Context
	actCancel context.CancelFunc

	latestConfigInput internal.ConfigInput

	logFile string

	oauthAuthFlow oauthAuthFlow

	mutex  sync.Mutex
	config *internal.Config
	proto.UnimplementedDaemonServiceServer

	connectClient *internal.ConnectClient

	statusRecorder *peer.Status
	sessionWatcher *internal.SessionWatcher

	mgmProbe    *internal.Probe
	signalProbe *internal.Probe
	relayProbe  *internal.Probe
	wgProbe     *internal.Probe
	lastProbe   time.Time
}

type oauthAuthFlow struct {
	expiresAt  time.Time
	flow       auth.OAuthFlow
	info       auth.AuthFlowInfo
	waitCancel context.CancelFunc
}

// New server instance constructor.
func New(ctx context.Context, configPath, logFile string) *Server {
	return &Server{
		rootCtx: ctx,
		latestConfigInput: internal.ConfigInput{
			ConfigPath: configPath,
		},
		logFile:     logFile,
		mgmProbe:    internal.NewProbe(),
		signalProbe: internal.NewProbe(),
		relayProbe:  internal.NewProbe(),
		wgProbe:     internal.NewProbe(),
	}
}

func (s *Server) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	state := internal.CtxGetState(s.rootCtx)

	// if current state contains any error, return it
	// in all other cases we can continue execution only if status is idle and up command was
	// not in the progress or already successfully established connection.
	status, err := state.Status()
	if err != nil {
		return err
	}

	if status != internal.StatusIdle {
		return nil
	}

	ctx, cancel := context.WithCancel(s.rootCtx)
	s.actCancel = cancel

	// if configuration exists, we just start connections. if is new config we skip and set status NeedsLogin
	// on failure we return error to retry
	config, err := internal.UpdateConfig(s.latestConfigInput)
	if errorStatus, ok := gstatus.FromError(err); ok && errorStatus.Code() == codes.NotFound {
		s.config, err = internal.UpdateOrCreateConfig(s.latestConfigInput)
		if err != nil {
			log.Warnf("unable to create configuration file: %v", err)
			return err
		}
		state.Set(internal.StatusNeedsLogin)
		return nil
	} else if err != nil {
		log.Warnf("unable to create configuration file: %v", err)
		return err
	}

	// if configuration exists, we just start connections.
	config, _ = internal.UpdateOldManagementURL(ctx, config, s.latestConfigInput.ConfigPath)

	s.config = config

	if s.statusRecorder == nil {
		s.statusRecorder = peer.NewRecorder(config.ManagementURL.String())
	}
	s.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)

	if s.sessionWatcher == nil {
		s.sessionWatcher = internal.NewSessionWatcher(s.rootCtx, s.statusRecorder)
		s.sessionWatcher.SetOnExpireListener(s.onSessionExpire)
	}

	if !config.DisableAutoConnect {
		go s.connectWithRetryRuns(ctx, config, s.statusRecorder, s.mgmProbe, s.signalProbe, s.relayProbe, s.wgProbe)
	}

	return nil
}

// connectWithRetryRuns runs the client connection with a backoff strategy where we retry the operation as additional
// mechanism to keep the client connected even when the connection is lost.
// we cancel retry if the client receive a stop or down command, or if disable auto connect is configured.
func (s *Server) connectWithRetryRuns(ctx context.Context, config *internal.Config, statusRecorder *peer.Status,
	mgmProbe *internal.Probe, signalProbe *internal.Probe, relayProbe *internal.Probe, wgProbe *internal.Probe,
) {
	backOff := getConnectWithBackoff(ctx)
	retryStarted := false

	go func() {
		t := time.NewTicker(24 * time.Hour)
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				if retryStarted {

					mgmtState := statusRecorder.GetManagementState()
					signalState := statusRecorder.GetSignalState()
					if mgmtState.Connected && signalState.Connected {
						log.Tracef("resetting status")
						retryStarted = false
					} else {
						log.Tracef("not resetting status: mgmt: %v, signal: %v", mgmtState.Connected, signalState.Connected)
					}
				}
			}
		}
	}()

	runOperation := func() error {
		log.Tracef("running client connection")
		s.connectClient = internal.NewConnectClient(ctx, config, statusRecorder)
		err := s.connectClient.RunWithProbes(mgmProbe, signalProbe, relayProbe, wgProbe)
		if err != nil {
			log.Debugf("run client connection exited with error: %v. Will retry in the background", err)
		}

		if config.DisableAutoConnect {
			return backoff.Permanent(err)
		}

		if !retryStarted {
			retryStarted = true
			backOff.Reset()
		}

		log.Tracef("client connection exited")
		return fmt.Errorf("client connection exited")
	}

	err := backoff.Retry(runOperation, backOff)
	if s, ok := gstatus.FromError(err); ok && s.Code() != codes.Canceled {
		log.Errorf("received an error when trying to connect: %v", err)
	} else {
		log.Tracef("retry canceled")
	}
}

// getConnectWithBackoff returns a backoff with exponential backoff strategy for connection retries
func getConnectWithBackoff(ctx context.Context) backoff.BackOff {
	initialInterval := parseEnvDuration(retryInitialIntervalVar, defaultInitialRetryTime)
	maxInterval := parseEnvDuration(maxRetryIntervalVar, defaultMaxRetryInterval)
	maxElapsedTime := parseEnvDuration(maxRetryTimeVar, defaultMaxRetryTime)
	multiplier := defaultRetryMultiplier

	if envValue := os.Getenv(retryMultiplierVar); envValue != "" {
		// parse the multiplier from the environment variable string value to float64
		value, err := strconv.ParseFloat(envValue, 64)
		if err != nil {
			log.Warnf("unable to parse environment variable %s: %s. using default: %f", retryMultiplierVar, envValue, multiplier)
		} else {
			multiplier = value
		}
	}

	return backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     initialInterval,
		RandomizationFactor: 1,
		Multiplier:          multiplier,
		MaxInterval:         maxInterval,
		MaxElapsedTime:      maxElapsedTime, // 14 days
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)
}

// parseEnvDuration parses the environment variable and returns the duration
func parseEnvDuration(envVar string, defaultDuration time.Duration) time.Duration {
	if envValue := os.Getenv(envVar); envValue != "" {
		if duration, err := time.ParseDuration(envValue); err == nil {
			return duration
		}
		log.Warnf("unable to parse environment variable %s: %s. using default: %s", envVar, envValue, defaultDuration)
	}
	return defaultDuration
}

// loginAttempt attempts to login using the provided information. it returns a status in case something fails
func (s *Server) loginAttempt(ctx context.Context, setupKey, jwtToken string) (internal.StatusType, error) {
	var status internal.StatusType
	err := internal.Login(ctx, s.config, setupKey, jwtToken)
	if err != nil {
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			log.Warnf("failed login: %v", err)
			status = internal.StatusNeedsLogin
		} else {
			log.Errorf("failed login: %v", err)
			status = internal.StatusLoginFailed
		}
		return status, err
	}
	return "", nil
}

// Login uses setup key to prepare configuration for the daemon.
func (s *Server) Login(callerCtx context.Context, msg *proto.LoginRequest) (*proto.LoginResponse, error) {
	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)

	md, ok := metadata.FromIncomingContext(callerCtx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	s.actCancel = cancel
	s.mutex.Unlock()

	state := internal.CtxGetState(ctx)
	defer func() {
		status, err := state.Status()
		if err != nil || (status != internal.StatusNeedsLogin && status != internal.StatusLoginFailed) {
			state.Set(internal.StatusIdle)
		}
	}()

	s.mutex.Lock()
	inputConfig := s.latestConfigInput

	if msg.ManagementUrl != "" {
		inputConfig.ManagementURL = msg.ManagementUrl
		s.latestConfigInput.ManagementURL = msg.ManagementUrl
	}

	if msg.AdminURL != "" {
		inputConfig.AdminURL = msg.AdminURL
		s.latestConfigInput.AdminURL = msg.AdminURL
	}

	if msg.CleanNATExternalIPs {
		inputConfig.NATExternalIPs = make([]string, 0)
		s.latestConfigInput.NATExternalIPs = nil
	} else if msg.NatExternalIPs != nil {
		inputConfig.NATExternalIPs = msg.NatExternalIPs
		s.latestConfigInput.NATExternalIPs = msg.NatExternalIPs
	}

	inputConfig.CustomDNSAddress = msg.CustomDNSAddress
	s.latestConfigInput.CustomDNSAddress = msg.CustomDNSAddress
	if string(msg.CustomDNSAddress) == "empty" {
		inputConfig.CustomDNSAddress = []byte{}
		s.latestConfigInput.CustomDNSAddress = []byte{}
	}

	if msg.Hostname != "" {
		// nolint
		ctx = context.WithValue(ctx, system.DeviceNameCtxKey, msg.Hostname)
	}

	if msg.RosenpassEnabled != nil {
		inputConfig.RosenpassEnabled = msg.RosenpassEnabled
		s.latestConfigInput.RosenpassEnabled = msg.RosenpassEnabled
	}

	if msg.RosenpassPermissive != nil {
		inputConfig.RosenpassPermissive = msg.RosenpassPermissive
		s.latestConfigInput.RosenpassPermissive = msg.RosenpassPermissive
	}

	if msg.ServerSSHAllowed != nil {
		inputConfig.ServerSSHAllowed = msg.ServerSSHAllowed
		s.latestConfigInput.ServerSSHAllowed = msg.ServerSSHAllowed
	}

	if msg.DisableAutoConnect != nil {
		inputConfig.DisableAutoConnect = msg.DisableAutoConnect
		s.latestConfigInput.DisableAutoConnect = msg.DisableAutoConnect
	}

	if msg.InterfaceName != nil {
		inputConfig.InterfaceName = msg.InterfaceName
		s.latestConfigInput.InterfaceName = msg.InterfaceName
	}

	if msg.WireguardPort != nil {
		port := int(*msg.WireguardPort)
		inputConfig.WireguardPort = &port
		s.latestConfigInput.WireguardPort = &port
	}

	if msg.NetworkMonitor != nil {
		inputConfig.NetworkMonitor = msg.NetworkMonitor
		s.latestConfigInput.NetworkMonitor = msg.NetworkMonitor
	}

	if len(msg.ExtraIFaceBlacklist) > 0 {
		inputConfig.ExtraIFaceBlackList = msg.ExtraIFaceBlacklist
		s.latestConfigInput.ExtraIFaceBlackList = msg.ExtraIFaceBlacklist
	}

	s.mutex.Unlock()

	if msg.OptionalPreSharedKey != nil {
		inputConfig.PreSharedKey = msg.OptionalPreSharedKey
	}

	config, err := internal.UpdateOrCreateConfig(inputConfig)
	if err != nil {
		return nil, err
	}

	if msg.ManagementUrl == "" {
		config, _ = internal.UpdateOldManagementURL(ctx, config, s.latestConfigInput.ConfigPath)
		s.config = config
		s.latestConfigInput.ManagementURL = config.ManagementURL.String()
	}

	s.mutex.Lock()
	s.config = config
	s.mutex.Unlock()

	if _, err := s.loginAttempt(ctx, "", ""); err == nil {
		state.Set(internal.StatusIdle)
		return &proto.LoginResponse{}, nil
	}

	state.Set(internal.StatusConnecting)

	if msg.SetupKey == "" {
		oAuthFlow, err := auth.NewOAuthFlow(ctx, config, msg.IsLinuxDesktopClient)
		if err != nil {
			state.Set(internal.StatusLoginFailed)
			return nil, err
		}

		if s.oauthAuthFlow.flow != nil && s.oauthAuthFlow.flow.GetClientID(ctx) == oAuthFlow.GetClientID(context.TODO()) {
			if s.oauthAuthFlow.expiresAt.After(time.Now().Add(90 * time.Second)) {
				log.Debugf("using previous oauth flow info")
				return &proto.LoginResponse{
					NeedsSSOLogin:           true,
					VerificationURI:         s.oauthAuthFlow.info.VerificationURI,
					VerificationURIComplete: s.oauthAuthFlow.info.VerificationURIComplete,
					UserCode:                s.oauthAuthFlow.info.UserCode,
				}, nil
			} else {
				log.Warnf("canceling previous waiting execution")
				if s.oauthAuthFlow.waitCancel != nil {
					s.oauthAuthFlow.waitCancel()
				}
			}
		}

		authInfo, err := oAuthFlow.RequestAuthInfo(context.TODO())
		if err != nil {
			log.Errorf("getting a request OAuth flow failed: %v", err)
			return nil, err
		}

		s.mutex.Lock()
		s.oauthAuthFlow.flow = oAuthFlow
		s.oauthAuthFlow.info = authInfo
		s.oauthAuthFlow.expiresAt = time.Now().Add(time.Duration(authInfo.ExpiresIn) * time.Second)
		s.mutex.Unlock()

		state.Set(internal.StatusNeedsLogin)

		return &proto.LoginResponse{
			NeedsSSOLogin:           true,
			VerificationURI:         authInfo.VerificationURI,
			VerificationURIComplete: authInfo.VerificationURIComplete,
			UserCode:                authInfo.UserCode,
		}, nil
	}

	if loginStatus, err := s.loginAttempt(ctx, msg.SetupKey, ""); err != nil {
		state.Set(loginStatus)
		return nil, err
	}

	return &proto.LoginResponse{}, nil
}

// WaitSSOLogin uses the userCode to validate the TokenInfo and
// waits for the user to continue with the login on a browser
func (s *Server) WaitSSOLogin(callerCtx context.Context, msg *proto.WaitSSOLoginRequest) (*proto.WaitSSOLoginResponse, error) {
	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)

	md, ok := metadata.FromIncomingContext(callerCtx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	if msg.Hostname != "" {
		// nolint
		ctx = context.WithValue(ctx, system.DeviceNameCtxKey, msg.Hostname)
	}

	s.actCancel = cancel
	s.mutex.Unlock()

	if s.oauthAuthFlow.flow == nil {
		return nil, gstatus.Errorf(codes.Internal, "oauth flow is not initialized")
	}

	state := internal.CtxGetState(ctx)
	defer func() {
		s, err := state.Status()
		if err != nil || (s != internal.StatusNeedsLogin && s != internal.StatusLoginFailed) {
			state.Set(internal.StatusIdle)
		}
	}()

	state.Set(internal.StatusConnecting)

	s.mutex.Lock()
	flowInfo := s.oauthAuthFlow.info
	s.mutex.Unlock()

	if flowInfo.UserCode != msg.UserCode {
		state.Set(internal.StatusLoginFailed)
		return nil, gstatus.Errorf(codes.InvalidArgument, "sso user code is invalid")
	}

	if s.oauthAuthFlow.waitCancel != nil {
		s.oauthAuthFlow.waitCancel()
	}

	waitTimeout := time.Until(s.oauthAuthFlow.expiresAt)
	waitCTX, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()

	s.mutex.Lock()
	s.oauthAuthFlow.waitCancel = cancel
	s.mutex.Unlock()

	tokenInfo, err := s.oauthAuthFlow.flow.WaitToken(waitCTX, flowInfo)
	if err != nil {
		if err == context.Canceled {
			return nil, nil //nolint:nilnil
		}
		s.mutex.Lock()
		s.oauthAuthFlow.expiresAt = time.Now()
		s.mutex.Unlock()
		state.Set(internal.StatusLoginFailed)
		log.Errorf("waiting for browser login failed: %v", err)
		return nil, err
	}

	s.mutex.Lock()
	s.oauthAuthFlow.expiresAt = time.Now()
	s.mutex.Unlock()

	if loginStatus, err := s.loginAttempt(ctx, "", tokenInfo.GetTokenToUse()); err != nil {
		state.Set(loginStatus)
		return nil, err
	}

	return &proto.WaitSSOLoginResponse{}, nil
}

// Up starts engine work in the daemon.
func (s *Server) Up(callerCtx context.Context, _ *proto.UpRequest) (*proto.UpResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	state := internal.CtxGetState(s.rootCtx)

	// if current state contains any error, return it
	// in all other cases we can continue execution only if status is idle and up command was
	// not in the progress or already successfully established connection.
	status, err := state.Status()
	if err != nil {
		return nil, err
	}
	if status != internal.StatusIdle {
		return nil, fmt.Errorf("up already in progress: current status %s", status)
	}

	// it should be nil here, but .
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)

	md, ok := metadata.FromIncomingContext(callerCtx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	s.actCancel = cancel

	if s.config == nil {
		return nil, fmt.Errorf("config is not defined, please call login command first")
	}

	if s.statusRecorder == nil {
		s.statusRecorder = peer.NewRecorder(s.config.ManagementURL.String())
	}
	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)

	go s.connectWithRetryRuns(ctx, s.config, s.statusRecorder, s.mgmProbe, s.signalProbe, s.relayProbe, s.wgProbe)

	return &proto.UpResponse{}, nil
}

// Down engine work in the daemon.
func (s *Server) Down(_ context.Context, _ *proto.DownRequest) (*proto.DownResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.actCancel == nil {
		return nil, fmt.Errorf("service is not up")
	}
	s.actCancel()
	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusIdle)

	return &proto.DownResponse{}, nil
}

// Status returns the daemon status
func (s *Server) Status(
	_ context.Context,
	msg *proto.StatusRequest,
) (*proto.StatusResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	status, err := internal.CtxGetState(s.rootCtx).Status()
	if err != nil {
		return nil, err
	}

	statusResponse := proto.StatusResponse{Status: string(status), DaemonVersion: version.NetbirdVersion()}

	if s.statusRecorder == nil {
		s.statusRecorder = peer.NewRecorder(s.config.ManagementURL.String())
	}
	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)

	if msg.GetFullPeerStatus {
		s.runProbes()

		fullStatus := s.statusRecorder.GetFullStatus()
		pbFullStatus := toProtoFullStatus(fullStatus)
		statusResponse.FullStatus = pbFullStatus
	}

	return &statusResponse, nil
}

func (s *Server) runProbes() {
	if time.Since(s.lastProbe) > probeThreshold {
		managementHealthy := s.mgmProbe.Probe()
		signalHealthy := s.signalProbe.Probe()
		relayHealthy := s.relayProbe.Probe()
		wgProbe := s.wgProbe.Probe()

		// Update last time only if all probes were successful
		if managementHealthy && signalHealthy && relayHealthy && wgProbe {
			s.lastProbe = time.Now()
		}
	}
}

// GetConfig of the daemon.
func (s *Server) GetConfig(_ context.Context, _ *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	managementURL := s.latestConfigInput.ManagementURL
	adminURL := s.latestConfigInput.AdminURL
	preSharedKey := ""

	if s.config != nil {
		if managementURL == "" && s.config.ManagementURL != nil {
			managementURL = s.config.ManagementURL.String()
		}

		if s.config.AdminURL != nil {
			adminURL = s.config.AdminURL.String()
		}

		preSharedKey = s.config.PreSharedKey
		if preSharedKey != "" {
			preSharedKey = "**********"
		}

	}

	return &proto.GetConfigResponse{
		ManagementUrl: managementURL,
		AdminURL:      adminURL,
		ConfigFile:    s.latestConfigInput.ConfigPath,
		LogFile:       s.logFile,
		PreSharedKey:  preSharedKey,
	}, nil
}
func (s *Server) onSessionExpire() {
	if runtime.GOOS != "windows" {
		isUIActive := internal.CheckUIApp()
		if !isUIActive {
			if err := sendTerminalNotification(); err != nil {
				log.Errorf("send session expire terminal notification: %v", err)
			}
		}
	}
}

func toProtoFullStatus(fullStatus peer.FullStatus) *proto.FullStatus {
	pbFullStatus := proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
		Peers:           []*proto.PeerState{},
	}

	pbFullStatus.ManagementState.URL = fullStatus.ManagementState.URL
	pbFullStatus.ManagementState.Connected = fullStatus.ManagementState.Connected
	if err := fullStatus.ManagementState.Error; err != nil {
		pbFullStatus.ManagementState.Error = err.Error()
	}

	pbFullStatus.SignalState.URL = fullStatus.SignalState.URL
	pbFullStatus.SignalState.Connected = fullStatus.SignalState.Connected
	if err := fullStatus.SignalState.Error; err != nil {
		pbFullStatus.SignalState.Error = err.Error()
	}

	pbFullStatus.LocalPeerState.IP = fullStatus.LocalPeerState.IP
	pbFullStatus.LocalPeerState.PubKey = fullStatus.LocalPeerState.PubKey
	pbFullStatus.LocalPeerState.KernelInterface = fullStatus.LocalPeerState.KernelInterface
	pbFullStatus.LocalPeerState.Fqdn = fullStatus.LocalPeerState.FQDN
	pbFullStatus.LocalPeerState.RosenpassPermissive = fullStatus.RosenpassState.Permissive
	pbFullStatus.LocalPeerState.RosenpassEnabled = fullStatus.RosenpassState.Enabled
	pbFullStatus.LocalPeerState.Routes = maps.Keys(fullStatus.LocalPeerState.Routes)

	for _, peerState := range fullStatus.Peers {
		pbPeerState := &proto.PeerState{
			IP:                         peerState.IP,
			PubKey:                     peerState.PubKey,
			ConnStatus:                 peerState.ConnStatus.String(),
			ConnStatusUpdate:           timestamppb.New(peerState.ConnStatusUpdate),
			Relayed:                    peerState.Relayed,
			Direct:                     peerState.Direct,
			LocalIceCandidateType:      peerState.LocalIceCandidateType,
			RemoteIceCandidateType:     peerState.RemoteIceCandidateType,
			LocalIceCandidateEndpoint:  peerState.LocalIceCandidateEndpoint,
			RemoteIceCandidateEndpoint: peerState.RemoteIceCandidateEndpoint,
			Fqdn:                       peerState.FQDN,
			LastWireguardHandshake:     timestamppb.New(peerState.LastWireguardHandshake),
			BytesRx:                    peerState.BytesRx,
			BytesTx:                    peerState.BytesTx,
			RosenpassEnabled:           peerState.RosenpassEnabled,
			Routes:                     maps.Keys(peerState.GetRoutes()),
			Latency:                    durationpb.New(peerState.Latency),
		}
		pbFullStatus.Peers = append(pbFullStatus.Peers, pbPeerState)
	}

	for _, relayState := range fullStatus.Relays {
		pbRelayState := &proto.RelayState{
			URI:       relayState.URI.String(),
			Available: relayState.Err == nil,
		}
		if err := relayState.Err; err != nil {
			pbRelayState.Error = err.Error()
		}
		pbFullStatus.Relays = append(pbFullStatus.Relays, pbRelayState)
	}

	for _, dnsState := range fullStatus.NSGroupStates {
		var err string
		if dnsState.Error != nil {
			err = dnsState.Error.Error()
		}
		pbDnsState := &proto.NSGroupState{
			Servers: dnsState.Servers,
			Domains: dnsState.Domains,
			Enabled: dnsState.Enabled,
			Error:   err,
		}
		pbFullStatus.DnsServers = append(pbFullStatus.DnsServers, pbDnsState)
	}

	return &pbFullStatus
}

// sendTerminalNotification sends a terminal notification message
// to inform the user that the NetBird connection session has expired.
func sendTerminalNotification() error {
	message := "NetBird connection session expired\n\nPlease re-authenticate to connect to the network."
	echoCmd := exec.Command("echo", message)
	wallCmd := exec.Command("sudo", "wall")

	echoCmdStdout, err := echoCmd.StdoutPipe()
	if err != nil {
		return err
	}
	wallCmd.Stdin = echoCmdStdout

	if err := echoCmd.Start(); err != nil {
		return err
	}

	if err := wallCmd.Start(); err != nil {
		return err
	}

	if err := echoCmd.Wait(); err != nil {
		return err
	}

	return wallCmd.Wait()
}
