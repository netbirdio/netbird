package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/expose"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	sleephandler "github.com/netbirdio/netbird/client/internal/sleep/handler"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/domain"

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

	// JWT token cache TTL for the client daemon (disabled by default)
	defaultJWTCacheTTL = 0

	errRestoreResidualState   = "failed to restore residual state: %v"
	errProfilesDisabled       = "profiles are disabled, you cannot use this feature without profiles enabled"
	errUpdateSettingsDisabled = "update settings are disabled, you cannot use this feature without update settings enabled"
)

var ErrServiceNotUp = errors.New("service is not up")

// Server for service control.
type Server struct {
	rootCtx   context.Context
	actCancel context.CancelFunc

	logFile string

	oauthAuthFlow oauthAuthFlow

	mutex  sync.Mutex
	config *profilemanager.Config
	proto.UnimplementedDaemonServiceServer
	clientRunning     bool // protected by mutex
	clientRunningChan chan struct{}
	clientGiveUpChan  chan struct{} // closed when connectWithRetryRuns goroutine exits

	connectClient *internal.ConnectClient

	statusRecorder *peer.Status
	sessionWatcher *internal.SessionWatcher

	lastProbe           time.Time
	persistSyncResponse bool
	isSessionActive     atomic.Bool

	cpuProfileBuf *bytes.Buffer
	cpuProfiling  bool

	profileManager         *profilemanager.ServiceManager
	profilesDisabled       bool
	updateSettingsDisabled bool

	sleepHandler *sleephandler.SleepHandler

	jwtCache *jwtCache
}

type oauthAuthFlow struct {
	expiresAt  time.Time
	flow       auth.OAuthFlow
	info       auth.AuthFlowInfo
	waitCancel context.CancelFunc
}

// New server instance constructor.
func New(ctx context.Context, logFile string, configFile string, profilesDisabled bool, updateSettingsDisabled bool) *Server {
	s := &Server{
		rootCtx:                ctx,
		logFile:                logFile,
		persistSyncResponse:    true,
		statusRecorder:         peer.NewRecorder(""),
		profileManager:         profilemanager.NewServiceManager(configFile),
		profilesDisabled:       profilesDisabled,
		updateSettingsDisabled: updateSettingsDisabled,
		jwtCache:               newJWTCache(),
	}
	agent := &serverAgent{s}
	s.sleepHandler = sleephandler.New(agent)

	return s
}

func (s *Server) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.clientRunning {
		return nil
	}

	state := internal.CtxGetState(s.rootCtx)

	if err := handlePanicLog(); err != nil {
		log.Warnf("failed to redirect stderr: %v", err)
	}

	if err := restoreResidualState(s.rootCtx, s.profileManager.GetStatePath()); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

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

	// copy old default config
	_, err = s.profileManager.CopyDefaultProfileIfNotExists()
	if err != nil && !errors.Is(err, profilemanager.ErrorOldDefaultConfigNotFound) {
		return err
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return fmt.Errorf("failed to get active profile state: %w", err)
	}

	config, existingConfig, err := s.getConfig(activeProf)
	if err != nil {
		log.Errorf("failed to get active profile config: %v", err)

		return err
	}
	s.config = config

	s.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)
	s.statusRecorder.UpdateLazyConnection(config.LazyConnectionEnabled)

	if s.sessionWatcher == nil {
		s.sessionWatcher = internal.NewSessionWatcher(s.rootCtx, s.statusRecorder)
		s.sessionWatcher.SetOnExpireListener(s.onSessionExpire)
	}

	if config.DisableAutoConnect {
		state.Set(internal.StatusIdle)
		return nil
	}

	if !existingConfig {
		log.Warnf("not trying to connect when configuration was just created")
		state.Set(internal.StatusNeedsLogin)
		return nil
	}

	s.clientRunning = true
	s.clientRunningChan = make(chan struct{})
	s.clientGiveUpChan = make(chan struct{})
	go s.connectWithRetryRuns(ctx, config, s.statusRecorder, false, s.clientRunningChan, s.clientGiveUpChan)
	return nil
}

// connectWithRetryRuns runs the client connection with a backoff strategy where we retry the operation as additional
// mechanism to keep the client connected even when the connection is lost.
// we cancel retry if the client receive a stop or down command, or if disable auto connect is configured.
func (s *Server) connectWithRetryRuns(ctx context.Context, profileConfig *profilemanager.Config, statusRecorder *peer.Status, doInitialAutoUpdate bool, runningChan chan struct{}, giveUpChan chan struct{}) {
	defer func() {
		s.mutex.Lock()
		s.clientRunning = false
		s.mutex.Unlock()
	}()

	if s.config.DisableAutoConnect {
		if err := s.connect(ctx, s.config, s.statusRecorder, doInitialAutoUpdate, runningChan); err != nil {
			log.Debugf("run client connection exited with error: %v", err)
		}
		log.Tracef("client connection exited")
		return
	}

	backOff := getConnectWithBackoff(ctx)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				mgmtState := statusRecorder.GetManagementState()
				signalState := statusRecorder.GetSignalState()
				if mgmtState.Connected && signalState.Connected {
					log.Tracef("resetting status")
					backOff.Reset()
				} else {
					log.Tracef("not resetting status: mgmt: %v, signal: %v", mgmtState.Connected, signalState.Connected)
				}
			}
		}
	}()

	runOperation := func() error {
		err := s.connect(ctx, profileConfig, statusRecorder, doInitialAutoUpdate, runningChan)
		doInitialAutoUpdate = false
		if err != nil {
			log.Debugf("run client connection exited with error: %v. Will retry in the background", err)
			return err
		}

		log.Tracef("client connection exited gracefully, do not need to retry")
		return nil
	}

	if err := backoff.Retry(runOperation, backOff); err != nil {
		log.Errorf("operation failed: %v", err)
	}

	if giveUpChan != nil {
		close(giveUpChan)
	}
}

// loginAttempt attempts to login using the provided information. it returns a status in case something fails
func (s *Server) loginAttempt(ctx context.Context, setupKey, jwtToken string) (internal.StatusType, error) {
	authClient, err := auth.NewAuth(ctx, s.config.PrivateKey, s.config.ManagementURL, s.config)
	if err != nil {
		log.Errorf("failed to create auth client: %v", err)
		return internal.StatusLoginFailed, err
	}
	defer authClient.Close()

	var status internal.StatusType
	err, isAuthError := authClient.Login(ctx, setupKey, jwtToken)
	if err != nil {
		if isAuthError {
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
func (s *Server) SetConfig(callerCtx context.Context, msg *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkUpdateSettingsDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errUpdateSettingsDisabled)
	}

	profState := profilemanager.ActiveProfileState{
		Name:     msg.ProfileName,
		Username: msg.Username,
	}

	profPath, err := profState.FilePath()
	if err != nil {
		log.Errorf("failed to get active profile file path: %v", err)
		return nil, fmt.Errorf("failed to get active profile file path: %w", err)
	}

	var config profilemanager.ConfigInput

	config.ConfigPath = profPath

	if msg.ManagementUrl != "" {
		config.ManagementURL = msg.ManagementUrl
	}

	if msg.AdminURL != "" {
		config.AdminURL = msg.AdminURL
	}

	if msg.InterfaceName != nil {
		config.InterfaceName = msg.InterfaceName
	}

	if msg.WireguardPort != nil {
		wgPort := int(*msg.WireguardPort)
		config.WireguardPort = &wgPort
	}

	if msg.OptionalPreSharedKey != nil {
		if *msg.OptionalPreSharedKey != "" {
			config.PreSharedKey = msg.OptionalPreSharedKey
		}
	}

	if msg.CleanDNSLabels {
		config.DNSLabels = domain.List{}

	} else if msg.DnsLabels != nil {
		dnsLabels := domain.FromPunycodeList(msg.DnsLabels)
		config.DNSLabels = dnsLabels
	}

	if msg.CleanNATExternalIPs {
		config.NATExternalIPs = make([]string, 0)
	} else if msg.NatExternalIPs != nil {
		config.NATExternalIPs = msg.NatExternalIPs
	}

	config.CustomDNSAddress = msg.CustomDNSAddress
	if string(msg.CustomDNSAddress) == "empty" {
		config.CustomDNSAddress = []byte{}
	}

	config.ExtraIFaceBlackList = msg.ExtraIFaceBlacklist

	if msg.DnsRouteInterval != nil {
		interval := msg.DnsRouteInterval.AsDuration()
		config.DNSRouteInterval = &interval
	}

	config.RosenpassEnabled = msg.RosenpassEnabled
	config.RosenpassPermissive = msg.RosenpassPermissive
	config.DisableAutoConnect = msg.DisableAutoConnect
	config.ServerSSHAllowed = msg.ServerSSHAllowed
	config.NetworkMonitor = msg.NetworkMonitor
	config.DisableClientRoutes = msg.DisableClientRoutes
	config.DisableServerRoutes = msg.DisableServerRoutes
	config.DisableDNS = msg.DisableDns
	config.DisableFirewall = msg.DisableFirewall
	config.BlockLANAccess = msg.BlockLanAccess
	config.DisableNotifications = msg.DisableNotifications
	config.LazyConnectionEnabled = msg.LazyConnectionEnabled
	config.BlockInbound = msg.BlockInbound
	config.EnableSSHRoot = msg.EnableSSHRoot
	config.EnableSSHSFTP = msg.EnableSSHSFTP
	config.EnableSSHLocalPortForwarding = msg.EnableSSHLocalPortForwarding
	config.EnableSSHRemotePortForwarding = msg.EnableSSHRemotePortForwarding
	if msg.DisableSSHAuth != nil {
		config.DisableSSHAuth = msg.DisableSSHAuth
	}
	if msg.SshJWTCacheTTL != nil {
		ttl := int(*msg.SshJWTCacheTTL)
		config.SSHJWTCacheTTL = &ttl
	}

	if msg.Mtu != nil {
		mtu := uint16(*msg.Mtu)
		config.MTU = &mtu
	}

	if _, err := profilemanager.UpdateConfig(config); err != nil {
		log.Errorf("failed to update profile config: %v", err)
		return nil, fmt.Errorf("failed to update profile config: %w", err)
	}

	return &proto.SetConfigResponse{}, nil
}

// Login uses setup key to prepare configuration for the daemon.
func (s *Server) Login(callerCtx context.Context, msg *proto.LoginRequest) (*proto.LoginResponse, error) {
	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(callerCtx)

	md, ok := metadata.FromIncomingContext(callerCtx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	s.actCancel = cancel
	s.mutex.Unlock()

	if err := restoreResidualState(s.rootCtx, s.profileManager.GetStatePath()); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	state := internal.CtxGetState(s.rootCtx)
	defer func() {
		status, err := state.Status()
		if err != nil || (status != internal.StatusNeedsLogin && status != internal.StatusLoginFailed) {
			state.Set(internal.StatusIdle)
		}
	}()

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	if msg.ProfileName != nil {
		if *msg.ProfileName != "default" && (msg.Username == nil || *msg.Username == "") {
			log.Errorf("profile name is set to %s, but username is not provided", *msg.ProfileName)
			return nil, fmt.Errorf("profile name is set to %s, but username is not provided", *msg.ProfileName)
		}

		var username string
		if *msg.ProfileName != "default" {
			username = *msg.Username
		}

		if *msg.ProfileName != activeProf.Name && username != activeProf.Username {
			if s.checkProfilesDisabled() {
				log.Errorf("profiles are disabled, you cannot use this feature without profiles enabled")
				return nil, gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
			}

			log.Infof("switching to profile %s for user '%s'", *msg.ProfileName, username)
			if err := s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
				Name:     *msg.ProfileName,
				Username: username,
			}); err != nil {
				log.Errorf("failed to set active profile state: %v", err)
				return nil, fmt.Errorf("failed to set active profile state: %w", err)
			}
		}
	}

	activeProf, err = s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	log.Infof("active profile: %s for %s", activeProf.Name, activeProf.Username)

	s.mutex.Lock()

	if msg.Hostname != "" {
		// nolint
		ctx = context.WithValue(ctx, system.DeviceNameCtxKey, msg.Hostname)
	}

	s.mutex.Unlock()

	config, _, err := s.getConfig(activeProf)
	if err != nil {
		log.Errorf("failed to get active profile config: %v", err)
		return nil, fmt.Errorf("failed to get active profile config: %w", err)
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
		hint := ""
		if msg.Hint != nil {
			hint = *msg.Hint
		}
		oAuthFlow, err := auth.NewOAuthFlow(ctx, config, msg.IsUnixDesktopClient, false, hint)
		if err != nil {
			state.Set(internal.StatusLoginFailed)
			return nil, err
		}

		if s.oauthAuthFlow.flow != nil && s.oauthAuthFlow.flow.GetClientID(ctx) == oAuthFlow.GetClientID(ctx) {
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

		authInfo, err := oAuthFlow.RequestAuthInfo(ctx)
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

	waitCTX, cancel := context.WithCancel(ctx)
	defer cancel()

	s.mutex.Lock()
	s.oauthAuthFlow.waitCancel = cancel
	s.mutex.Unlock()

	tokenInfo, err := s.oauthAuthFlow.flow.WaitToken(waitCTX, flowInfo)
	if err != nil {
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

	return &proto.WaitSSOLoginResponse{
		Email: tokenInfo.Email,
	}, nil
}

// Up starts engine work in the daemon.
func (s *Server) Up(callerCtx context.Context, msg *proto.UpRequest) (*proto.UpResponse, error) {
	s.mutex.Lock()
	if s.clientRunning {
		state := internal.CtxGetState(s.rootCtx)
		status, err := state.Status()
		if err != nil {
			s.mutex.Unlock()
			return nil, err
		}
		if status == internal.StatusNeedsLogin {
			s.actCancel()
		}
		s.mutex.Unlock()

		return s.waitForUp(callerCtx)
	}
	if err := restoreResidualState(callerCtx, s.profileManager.GetStatePath()); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	state := internal.CtxGetState(s.rootCtx)

	// if current state contains any error, return it
	// in all other cases we can continue execution only if status is idle and up command was
	// not in the progress or already successfully established connection.
	status, err := state.Status()
	if err != nil {
		s.mutex.Unlock()
		return nil, err
	}

	if status != internal.StatusIdle {
		s.mutex.Unlock()
		return nil, fmt.Errorf("up already in progress: current status %s", status)
	}

	// it should be nil here, but in case it isn't we cancel it.
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
		s.mutex.Unlock()
		return nil, fmt.Errorf("config is not defined, please call login command first")
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		s.mutex.Unlock()
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	if msg != nil && msg.ProfileName != nil {
		if err := s.switchProfileIfNeeded(*msg.ProfileName, msg.Username, activeProf); err != nil {
			s.mutex.Unlock()
			log.Errorf("failed to switch profile: %v", err)
			return nil, fmt.Errorf("failed to switch profile: %w", err)
		}
	}

	activeProf, err = s.profileManager.GetActiveProfileState()
	if err != nil {
		s.mutex.Unlock()
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	log.Infof("active profile: %s for %s", activeProf.Name, activeProf.Username)

	config, _, err := s.getConfig(activeProf)
	if err != nil {
		s.mutex.Unlock()
		log.Errorf("failed to get active profile config: %v", err)
		return nil, fmt.Errorf("failed to get active profile config: %w", err)
	}
	s.config = config

	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)

	s.clientRunning = true
	s.clientRunningChan = make(chan struct{})
	s.clientGiveUpChan = make(chan struct{})

	var doAutoUpdate bool
	if msg != nil && msg.AutoUpdate != nil && *msg.AutoUpdate {
		doAutoUpdate = true
	}
	go s.connectWithRetryRuns(ctx, s.config, s.statusRecorder, doAutoUpdate, s.clientRunningChan, s.clientGiveUpChan)

	s.mutex.Unlock()
	return s.waitForUp(callerCtx)
}

// todo: handle potential race conditions
func (s *Server) waitForUp(callerCtx context.Context) (*proto.UpResponse, error) {
	timeoutCtx, cancel := context.WithTimeout(callerCtx, 50*time.Second)
	defer cancel()

	select {
	case <-s.clientGiveUpChan:
		return nil, fmt.Errorf("client gave up to connect")
	case <-s.clientRunningChan:
		s.isSessionActive.Store(true)
		return &proto.UpResponse{}, nil
	case <-callerCtx.Done():
		log.Debug("context done, stopping the wait for engine to become ready")
		return nil, callerCtx.Err()
	case <-timeoutCtx.Done():
		log.Debug("up is timed out, stopping the wait for engine to become ready")
		return nil, timeoutCtx.Err()
	}
}

func (s *Server) switchProfileIfNeeded(profileName string, userName *string, activeProf *profilemanager.ActiveProfileState) error {
	if profileName != "default" && (userName == nil || *userName == "") {
		log.Errorf("profile name is set to %s, but username is not provided", profileName)
		return fmt.Errorf("profile name is set to %s, but username is not provided", profileName)
	}

	var username string
	if profileName != "default" {
		username = *userName
	}

	if profileName != activeProf.Name || username != activeProf.Username {
		if s.checkProfilesDisabled() {
			log.Errorf("profiles are disabled, you cannot use this feature without profiles enabled")
			return gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
		}

		log.Infof("switching to profile %s for user %s", profileName, username)
		if err := s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			Name:     profileName,
			Username: username,
		}); err != nil {
			log.Errorf("failed to set active profile state: %v", err)
			return fmt.Errorf("failed to set active profile state: %w", err)
		}
	}

	return nil
}

// SwitchProfile switches the active profile in the daemon.
func (s *Server) SwitchProfile(callerCtx context.Context, msg *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	if msg != nil && msg.ProfileName != nil {
		if err := s.switchProfileIfNeeded(*msg.ProfileName, msg.Username, activeProf); err != nil {
			log.Errorf("failed to switch profile: %v", err)
			return nil, fmt.Errorf("failed to switch profile: %w", err)
		}
	}
	activeProf, err = s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}
	config, _, err := s.getConfig(activeProf)
	if err != nil {
		log.Errorf("failed to get default profile config: %v", err)
		return nil, fmt.Errorf("failed to get default profile config: %w", err)
	}

	s.config = config

	return &proto.SwitchProfileResponse{}, nil
}

// Down engine work in the daemon.
func (s *Server) Down(ctx context.Context, _ *proto.DownRequest) (*proto.DownResponse, error) {
	s.mutex.Lock()

	giveUpChan := s.clientGiveUpChan

	if err := s.cleanupConnection(); err != nil {
		s.mutex.Unlock()
		// todo review to update the status in case any type of error
		log.Errorf("failed to shut down properly: %v", err)
		return nil, err
	}

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusIdle)

	s.mutex.Unlock()

	// Wait for the connectWithRetryRuns goroutine to finish with a short timeout.
	// This prevents the goroutine from setting ErrResetConnection after Down() returns.
	// The giveUpChan is closed at the end of connectWithRetryRuns.
	if giveUpChan != nil {
		select {
		case <-giveUpChan:
			log.Debugf("client goroutine finished successfully")
		case <-time.After(5 * time.Second):
			log.Warnf("timeout waiting for client goroutine to finish, proceeding anyway")
		}
	}

	return &proto.DownResponse{}, nil
}

func (s *Server) cleanupConnection() error {
	s.oauthAuthFlow = oauthAuthFlow{}

	if s.actCancel == nil {
		return ErrServiceNotUp
	}
	s.actCancel()

	if s.connectClient == nil {
		return nil
	}

	if err := s.connectClient.Stop(); err != nil {
		return err
	}

	s.connectClient = nil
	s.isSessionActive.Store(false)

	log.Infof("service is down")

	return nil
}

func (s *Server) Logout(ctx context.Context, msg *proto.LogoutRequest) (*proto.LogoutResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if msg.ProfileName != nil && *msg.ProfileName != "" {
		return s.handleProfileLogout(ctx, msg)
	}

	return s.handleActiveProfileLogout(ctx)
}

func (s *Server) handleProfileLogout(ctx context.Context, msg *proto.LogoutRequest) (*proto.LogoutResponse, error) {
	if err := s.validateProfileOperation(*msg.ProfileName, true); err != nil {
		return nil, err
	}

	if msg.Username == nil || *msg.Username == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "username must be provided when profile name is specified")
	}
	username := *msg.Username

	if err := s.logoutFromProfile(ctx, *msg.ProfileName, username); err != nil {
		log.Errorf("failed to logout from profile %s: %v", *msg.ProfileName, err)
		return nil, gstatus.Errorf(codes.Internal, "logout: %v", err)
	}

	activeProf, _ := s.profileManager.GetActiveProfileState()
	if activeProf != nil && activeProf.Name == *msg.ProfileName {
		if err := s.cleanupConnection(); err != nil && !errors.Is(err, ErrServiceNotUp) {
			log.Errorf("failed to cleanup connection: %v", err)
		}
		state := internal.CtxGetState(s.rootCtx)
		state.Set(internal.StatusNeedsLogin)
	}

	return &proto.LogoutResponse{}, nil
}

func (s *Server) handleActiveProfileLogout(ctx context.Context) (*proto.LogoutResponse, error) {
	if s.config == nil {
		activeProf, err := s.profileManager.GetActiveProfileState()
		if err != nil {
			return nil, gstatus.Errorf(codes.FailedPrecondition, "failed to get active profile state: %v", err)
		}

		config, _, err := s.getConfig(activeProf)
		if err != nil {
			return nil, gstatus.Errorf(codes.FailedPrecondition, "not logged in")
		}
		s.config = config
	}

	if err := s.sendLogoutRequest(ctx); err != nil {
		log.Errorf("failed to send logout request: %v", err)
		return nil, err
	}

	if err := s.cleanupConnection(); err != nil && !errors.Is(err, ErrServiceNotUp) {
		// todo review to update the status in case any type of error
		log.Errorf("failed to cleanup connection: %v", err)
		return nil, err
	}

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusNeedsLogin)

	return &proto.LogoutResponse{}, nil
}

// GetConfig reads config file and returns Config and whether the config file already existed. Errors out if it does not exist
func (s *Server) getConfig(activeProf *profilemanager.ActiveProfileState) (*profilemanager.Config, bool, error) {
	cfgPath, err := activeProf.FilePath()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get active profile file path: %w", err)
	}

	_, err = os.Stat(cfgPath)
	configExisted := !os.IsNotExist(err)

	log.Infof("active profile config existed: %t, err %v", configExisted, err)

	config, err := profilemanager.ReadConfig(cfgPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get config: %w", err)
	}

	return config, configExisted, nil
}

func (s *Server) canRemoveProfile(profileName string) error {
	if profileName == profilemanager.DefaultProfileName {
		return fmt.Errorf("remove profile with reserved name: %s", profilemanager.DefaultProfileName)
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err == nil && activeProf.Name == profileName {
		return fmt.Errorf("remove active profile: %s", profileName)
	}

	return nil
}

func (s *Server) validateProfileOperation(profileName string, allowActiveProfile bool) error {
	if s.checkProfilesDisabled() {
		return gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
	}

	if profileName == "" {
		return gstatus.Errorf(codes.InvalidArgument, "profile name must be provided")
	}

	if !allowActiveProfile {
		if err := s.canRemoveProfile(profileName); err != nil {
			return gstatus.Errorf(codes.InvalidArgument, "%v", err)
		}
	}

	return nil
}

// logoutFromProfile logs out from a specific profile by loading its config and sending logout request
func (s *Server) logoutFromProfile(ctx context.Context, profileName, username string) error {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err == nil && activeProf.Name == profileName && s.connectClient != nil {
		return s.sendLogoutRequest(ctx)
	}

	profileState := &profilemanager.ActiveProfileState{
		Name:     profileName,
		Username: username,
	}
	profilePath, err := profileState.FilePath()
	if err != nil {
		return fmt.Errorf("get profile path: %w", err)
	}

	config, err := profilemanager.GetConfig(profilePath)
	if err != nil {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	return s.sendLogoutRequestWithConfig(ctx, config)
}

func (s *Server) sendLogoutRequest(ctx context.Context) error {
	return s.sendLogoutRequestWithConfig(ctx, s.config)
}

func (s *Server) sendLogoutRequestWithConfig(ctx context.Context, config *profilemanager.Config) error {
	key, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	mgmTlsEnabled := config.ManagementURL.Scheme == "https"
	mgmClient, err := mgm.NewClient(ctx, config.ManagementURL.Host, key, mgmTlsEnabled)
	if err != nil {
		return fmt.Errorf("connect to management server: %w", err)
	}
	defer func() {
		if err := mgmClient.Close(); err != nil {
			log.Errorf("close management client: %v", err)
		}
	}()

	return mgmClient.Logout()
}

// Status returns the daemon status
func (s *Server) Status(
	ctx context.Context,
	msg *proto.StatusRequest,
) (*proto.StatusResponse, error) {
	s.mutex.Lock()
	clientRunning := s.clientRunning
	s.mutex.Unlock()

	if msg.WaitForReady != nil && *msg.WaitForReady && clientRunning {
		state := internal.CtxGetState(s.rootCtx)
		status, err := state.Status()
		if err != nil {
			return nil, err
		}

		if status != internal.StatusIdle && status != internal.StatusConnected && status != internal.StatusConnecting {
			s.actCancel()
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
	loop:
		for {
			select {
			case <-s.clientGiveUpChan:
				ticker.Stop()
				break loop
			case <-s.clientRunningChan:
				ticker.Stop()
				break loop
			case <-ticker.C:
				status, err := state.Status()
				if err != nil {
					continue
				}
				if status != internal.StatusIdle && status != internal.StatusConnected && status != internal.StatusConnecting {
					s.actCancel()
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	status, err := internal.CtxGetState(s.rootCtx).Status()
	if err != nil {
		return nil, err
	}

	if status == internal.StatusNeedsLogin && s.isSessionActive.Load() {
		log.Debug("status requested while session is active, returning SessionExpired")
		status = internal.StatusSessionExpired
		s.isSessionActive.Store(false)
	}

	statusResponse := proto.StatusResponse{Status: string(status), DaemonVersion: version.NetbirdVersion()}

	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)

	if msg.GetFullPeerStatus {
		s.runProbes(msg.ShouldRunProbes)
		fullStatus := s.statusRecorder.GetFullStatus()
		pbFullStatus := fullStatus.ToProto()
		pbFullStatus.Events = s.statusRecorder.GetEventHistory()
		pbFullStatus.SshServerState = s.getSSHServerState()
		statusResponse.FullStatus = pbFullStatus
	}

	return &statusResponse, nil
}

// getSSHServerState retrieves the current SSH server state including enabled status and active sessions
func (s *Server) getSSHServerState() *proto.SSHServerState {
	s.mutex.Lock()
	connectClient := s.connectClient
	s.mutex.Unlock()

	if connectClient == nil {
		return nil
	}

	engine := connectClient.Engine()
	if engine == nil {
		return nil
	}

	enabled, sessions := engine.GetSSHServerStatus()
	sshServerState := &proto.SSHServerState{
		Enabled: enabled,
	}

	for _, session := range sessions {
		sshServerState.Sessions = append(sshServerState.Sessions, &proto.SSHSessionInfo{
			Username:      session.Username,
			RemoteAddress: session.RemoteAddress,
			Command:       session.Command,
			JwtUsername:   session.JWTUsername,
			PortForwards:  session.PortForwards,
		})
	}

	return sshServerState
}

// GetPeerSSHHostKey retrieves SSH host key for a specific peer
func (s *Server) GetPeerSSHHostKey(
	ctx context.Context,
	req *proto.GetPeerSSHHostKeyRequest,
) (*proto.GetPeerSSHHostKeyResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	s.mutex.Lock()
	connectClient := s.connectClient
	statusRecorder := s.statusRecorder
	s.mutex.Unlock()

	if connectClient == nil {
		return nil, errors.New("client not initialized")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return nil, errors.New("engine not started")
	}

	peerAddress := req.GetPeerAddress()
	hostKey, found := engine.GetPeerSSHKey(peerAddress)

	response := &proto.GetPeerSSHHostKeyResponse{
		Found: found,
	}

	if !found {
		return response, nil
	}

	response.SshHostKey = hostKey

	if statusRecorder == nil {
		return response, nil
	}

	fullStatus := statusRecorder.GetFullStatus()
	for _, peerState := range fullStatus.Peers {
		if peerState.IP == peerAddress || peerState.FQDN == peerAddress {
			response.PeerIP = peerState.IP
			response.PeerFQDN = peerState.FQDN
			break
		}
	}

	return response, nil
}

// getJWTCacheTTL returns the JWT cache TTL from config or default (disabled)
func (s *Server) getJWTCacheTTL() time.Duration {
	s.mutex.Lock()
	config := s.config
	s.mutex.Unlock()

	if config == nil || config.SSHJWTCacheTTL == nil {
		return defaultJWTCacheTTL
	}

	seconds := *config.SSHJWTCacheTTL
	if seconds == 0 {
		log.Debug("SSH JWT cache disabled (configured to 0)")
		return 0
	}

	ttl := time.Duration(seconds) * time.Second
	log.Debugf("SSH JWT cache TTL set to %v from config", ttl)
	return ttl
}

// RequestJWTAuth initiates JWT authentication flow for SSH
func (s *Server) RequestJWTAuth(
	ctx context.Context,
	msg *proto.RequestJWTAuthRequest,
) (*proto.RequestJWTAuthResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	s.mutex.Lock()
	config := s.config
	s.mutex.Unlock()

	if config == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not configured")
	}

	jwtCacheTTL := s.getJWTCacheTTL()
	if jwtCacheTTL > 0 {
		if cachedToken, found := s.jwtCache.get(); found {
			log.Debugf("JWT token found in cache, returning cached token for SSH authentication")

			return &proto.RequestJWTAuthResponse{
				CachedToken: cachedToken,
				MaxTokenAge: int64(jwtCacheTTL.Seconds()),
			}, nil
		}
	}

	hint := ""
	if msg.Hint != nil {
		hint = *msg.Hint
	}

	if hint == "" {
		hint = profilemanager.GetLoginHint()
	}

	isDesktop := isUnixRunningDesktop()
	oAuthFlow, err := auth.NewOAuthFlow(ctx, config, isDesktop, false, hint)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "failed to create OAuth flow: %v", err)
	}

	authInfo, err := oAuthFlow.RequestAuthInfo(ctx)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "failed to request auth info: %v", err)
	}

	s.mutex.Lock()
	s.oauthAuthFlow.flow = oAuthFlow
	s.oauthAuthFlow.info = authInfo
	s.oauthAuthFlow.expiresAt = time.Now().Add(time.Duration(authInfo.ExpiresIn) * time.Second)
	s.mutex.Unlock()

	return &proto.RequestJWTAuthResponse{
		VerificationURI:         authInfo.VerificationURI,
		VerificationURIComplete: authInfo.VerificationURIComplete,
		UserCode:                authInfo.UserCode,
		DeviceCode:              authInfo.DeviceCode,
		ExpiresIn:               int64(authInfo.ExpiresIn),
		MaxTokenAge:             int64(jwtCacheTTL.Seconds()),
	}, nil
}

// WaitJWTToken waits for JWT authentication completion
func (s *Server) WaitJWTToken(
	ctx context.Context,
	req *proto.WaitJWTTokenRequest,
) (*proto.WaitJWTTokenResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	s.mutex.Lock()
	oAuthFlow := s.oauthAuthFlow.flow
	authInfo := s.oauthAuthFlow.info
	s.mutex.Unlock()

	if oAuthFlow == nil || authInfo.DeviceCode != req.DeviceCode {
		return nil, gstatus.Errorf(codes.InvalidArgument, "invalid device code or no active auth flow")
	}

	tokenInfo, err := oAuthFlow.WaitToken(ctx, authInfo)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "failed to get token: %v", err)
	}

	token := tokenInfo.GetTokenToUse()

	jwtCacheTTL := s.getJWTCacheTTL()
	if jwtCacheTTL > 0 {
		s.jwtCache.store(token, jwtCacheTTL)
		log.Debugf("JWT token cached for SSH authentication, TTL: %v", jwtCacheTTL)
	} else {
		log.Debug("JWT caching disabled, not storing token")
	}

	s.mutex.Lock()
	s.oauthAuthFlow = oauthAuthFlow{}
	s.mutex.Unlock()
	return &proto.WaitJWTTokenResponse{
		Token:     tokenInfo.GetTokenToUse(),
		TokenType: tokenInfo.TokenType,
		ExpiresIn: int64(tokenInfo.ExpiresIn),
	}, nil
}

// ExposeService exposes a local port via the NetBird reverse proxy.
func (s *Server) ExposeService(req *proto.ExposeServiceRequest, srv proto.DaemonService_ExposeServiceServer) error {
	s.mutex.Lock()
	if !s.clientRunning {
		s.mutex.Unlock()
		return gstatus.Errorf(codes.FailedPrecondition, "client is not running, run 'netbird up' first")
	}
	connectClient := s.connectClient
	s.mutex.Unlock()

	if connectClient == nil {
		return gstatus.Errorf(codes.FailedPrecondition, "client not initialized")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return gstatus.Errorf(codes.FailedPrecondition, "engine not initialized")
	}

	mgr := engine.GetExposeManager()
	if mgr == nil {
		return gstatus.Errorf(codes.Internal, "expose manager not available")
	}

	ctx := srv.Context()

	exposeCtx, exposeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer exposeCancel()

	mgmReq := expose.NewRequest(req)
	result, err := mgr.Expose(exposeCtx, *mgmReq)
	if err != nil {
		return err
	}

	if err := srv.Send(&proto.ExposeServiceEvent{
		Event: &proto.ExposeServiceEvent_Ready{
			Ready: &proto.ExposeServiceReady{
				ServiceName: result.ServiceName,
				ServiceUrl:  result.ServiceURL,
				Domain:      result.Domain,
			},
		},
	}); err != nil {
		return err
	}

	err = mgr.KeepAlive(ctx, result.Domain)
	if err != nil {
		return err
	}
	return nil
}

func isUnixRunningDesktop() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		return false
	}
	return os.Getenv("DESKTOP_SESSION") != "" || os.Getenv("XDG_CURRENT_DESKTOP") != ""
}

func (s *Server) runProbes(waitForProbeResult bool) {
	if s.connectClient == nil {
		return
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return
	}

	if time.Since(s.lastProbe) > probeThreshold {
		if engine.RunHealthProbes(waitForProbeResult) {
			s.lastProbe = time.Now()
		}
	} else {
		if err := s.statusRecorder.RefreshWireGuardStats(); err != nil {
			log.Debugf("failed to refresh WireGuard stats: %v", err)
		}
	}
}

// GetConfig of the daemon.
func (s *Server) GetConfig(ctx context.Context, req *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	prof := profilemanager.ActiveProfileState{
		Name:     req.ProfileName,
		Username: req.Username,
	}

	cfgPath, err := prof.FilePath()
	if err != nil {
		log.Errorf("failed to get active profile file path: %v", err)
		return nil, fmt.Errorf("failed to get active profile file path: %w", err)
	}

	cfg, err := profilemanager.GetConfig(cfgPath)
	if err != nil {
		log.Errorf("failed to get active profile config: %v", err)
		return nil, fmt.Errorf("failed to get active profile config: %w", err)
	}
	managementURL := cfg.ManagementURL
	adminURL := cfg.AdminURL

	var preSharedKey = cfg.PreSharedKey
	if preSharedKey != "" {
		preSharedKey = "**********"
	}

	disableNotifications := true
	if cfg.DisableNotifications != nil {
		disableNotifications = *cfg.DisableNotifications
	}

	networkMonitor := false
	if cfg.NetworkMonitor != nil {
		networkMonitor = *cfg.NetworkMonitor
	}

	disableDNS := cfg.DisableDNS
	disableClientRoutes := cfg.DisableClientRoutes
	disableServerRoutes := cfg.DisableServerRoutes
	blockLANAccess := cfg.BlockLANAccess

	enableSSHRoot := false
	if cfg.EnableSSHRoot != nil {
		enableSSHRoot = *cfg.EnableSSHRoot
	}

	enableSSHSFTP := false
	if cfg.EnableSSHSFTP != nil {
		enableSSHSFTP = *cfg.EnableSSHSFTP
	}

	enableSSHLocalPortForwarding := false
	if cfg.EnableSSHLocalPortForwarding != nil {
		enableSSHLocalPortForwarding = *cfg.EnableSSHLocalPortForwarding
	}

	enableSSHRemotePortForwarding := false
	if cfg.EnableSSHRemotePortForwarding != nil {
		enableSSHRemotePortForwarding = *cfg.EnableSSHRemotePortForwarding
	}

	disableSSHAuth := false
	if cfg.DisableSSHAuth != nil {
		disableSSHAuth = *cfg.DisableSSHAuth
	}

	sshJWTCacheTTL := int32(0)
	if cfg.SSHJWTCacheTTL != nil {
		sshJWTCacheTTL = int32(*cfg.SSHJWTCacheTTL)
	}

	return &proto.GetConfigResponse{
		ManagementUrl:                 managementURL.String(),
		PreSharedKey:                  preSharedKey,
		AdminURL:                      adminURL.String(),
		InterfaceName:                 cfg.WgIface,
		WireguardPort:                 int64(cfg.WgPort),
		Mtu:                           int64(cfg.MTU),
		DisableAutoConnect:            cfg.DisableAutoConnect,
		ServerSSHAllowed:              *cfg.ServerSSHAllowed,
		RosenpassEnabled:              cfg.RosenpassEnabled,
		RosenpassPermissive:           cfg.RosenpassPermissive,
		LazyConnectionEnabled:         cfg.LazyConnectionEnabled,
		BlockInbound:                  cfg.BlockInbound,
		DisableNotifications:          disableNotifications,
		NetworkMonitor:                networkMonitor,
		DisableDns:                    disableDNS,
		DisableClientRoutes:           disableClientRoutes,
		DisableServerRoutes:           disableServerRoutes,
		BlockLanAccess:                blockLANAccess,
		EnableSSHRoot:                 enableSSHRoot,
		EnableSSHSFTP:                 enableSSHSFTP,
		EnableSSHLocalPortForwarding:  enableSSHLocalPortForwarding,
		EnableSSHRemotePortForwarding: enableSSHRemotePortForwarding,
		DisableSSHAuth:                disableSSHAuth,
		SshJWTCacheTTL:                sshJWTCacheTTL,
	}, nil
}

// AddProfile adds a new profile to the daemon.
func (s *Server) AddProfile(ctx context.Context, msg *proto.AddProfileRequest) (*proto.AddProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkProfilesDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
	}

	if msg.ProfileName == "" || msg.Username == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "profile name and username must be provided")
	}

	if err := s.profileManager.AddProfile(msg.ProfileName, msg.Username); err != nil {
		log.Errorf("failed to create profile: %v", err)
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}

	return &proto.AddProfileResponse{}, nil
}

// RemoveProfile removes a profile from the daemon.
func (s *Server) RemoveProfile(ctx context.Context, msg *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.validateProfileOperation(msg.ProfileName, false); err != nil {
		return nil, err
	}

	if err := s.logoutFromProfile(ctx, msg.ProfileName, msg.Username); err != nil {
		log.Warnf("failed to logout from profile %s before removal: %v", msg.ProfileName, err)
	}

	if err := s.profileManager.RemoveProfile(msg.ProfileName, msg.Username); err != nil {
		log.Errorf("failed to remove profile: %v", err)
		return nil, fmt.Errorf("failed to remove profile: %w", err)
	}

	return &proto.RemoveProfileResponse{}, nil
}

// ListProfiles lists all profiles in the daemon.
func (s *Server) ListProfiles(ctx context.Context, msg *proto.ListProfilesRequest) (*proto.ListProfilesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if msg.Username == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "username must be provided")
	}

	profiles, err := s.profileManager.ListProfiles(msg.Username)
	if err != nil {
		log.Errorf("failed to list profiles: %v", err)
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}

	response := &proto.ListProfilesResponse{
		Profiles: make([]*proto.Profile, len(profiles)),
	}
	for i, profile := range profiles {
		response.Profiles[i] = &proto.Profile{
			Name:     profile.Name,
			IsActive: profile.IsActive,
		}
	}

	return response, nil
}

// GetActiveProfile returns the active profile in the daemon.
func (s *Server) GetActiveProfile(ctx context.Context, msg *proto.GetActiveProfileRequest) (*proto.GetActiveProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	activeProfile, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	return &proto.GetActiveProfileResponse{
		ProfileName: activeProfile.Name,
		Username:    activeProfile.Username,
	}, nil
}

// GetFeatures returns the features supported by the daemon.
func (s *Server) GetFeatures(ctx context.Context, msg *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	features := &proto.GetFeaturesResponse{
		DisableProfiles:       s.checkProfilesDisabled(),
		DisableUpdateSettings: s.checkUpdateSettingsDisabled(),
	}

	return features, nil
}

func (s *Server) connect(ctx context.Context, config *profilemanager.Config, statusRecorder *peer.Status, doInitialAutoUpdate bool, runningChan chan struct{}) error {
	log.Tracef("running client connection")
	s.connectClient = internal.NewConnectClient(ctx, config, statusRecorder, doInitialAutoUpdate)
	s.connectClient.SetSyncResponsePersistence(s.persistSyncResponse)
	if err := s.connectClient.Run(runningChan, s.logFile); err != nil {
		return err
	}
	return nil
}

func (s *Server) checkProfilesDisabled() bool {
	// Check if the environment variable is set to disable profiles
	if s.profilesDisabled {
		return true
	}

	return false
}

func (s *Server) checkUpdateSettingsDisabled() bool {
	// Check if the environment variable is set to disable profiles
	if s.updateSettingsDisabled {
		return true
	}

	return false
}

func (s *Server) onSessionExpire() {
	if runtime.GOOS != "windows" {
		isUIActive := internal.CheckUIApp()
		if !isUIActive && s.config.DisableNotifications != nil && !*s.config.DisableNotifications {
			if err := sendTerminalNotification(); err != nil {
				log.Errorf("send session expire terminal notification: %v", err)
			}
		}
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
