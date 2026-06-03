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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/expose"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	sleephandler "github.com/netbirdio/netbird/client/internal/sleep/handler"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/updater"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util/capture"
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
	errNetworksDisabled       = "network selection is disabled by the administrator"
)

var ErrServiceNotUp = errors.New("service is not up")

// Server for service control.
type Server struct {
	rootCtx   context.Context
	actCancel context.CancelFunc

	logFile string

	oauthAuthFlow oauthAuthFlow
	// extendAuthSessionFlow holds the pending PKCE flow created by
	// RequestExtendAuthSession until WaitExtendAuthSession resolves it.
	// Kept separate from oauthAuthFlow (which is reserved for the SSH
	// JWT path) so a concurrent SSH auth doesn't clobber the session
	// extend flow or vice versa.
	extendAuthSessionFlow *auth.PendingFlow

	mutex  sync.Mutex
	config *profilemanager.Config
	proto.UnimplementedDaemonServiceServer
	clientRunning     bool // protected by mutex
	clientRunningChan chan struct{}
	clientGiveUpChan  chan struct{} // closed when connectWithRetryRuns goroutine exits

	connectClient *internal.ConnectClient

	statusRecorder *peer.Status
	sessionWatcher *internal.SessionWatcher

	probeThrottle       *probeThrottle
	persistSyncResponse bool
	isSessionActive     atomic.Bool

	cpuProfileBuf *bytes.Buffer
	cpuProfiling  bool

	profileManager         *profilemanager.ServiceManager
	profilesDisabled       bool
	updateSettingsDisabled bool
	captureEnabled         bool
	bundleCapture          *bundleCapture
	// activeCapture is the session currently installed on the engine; guarded by s.mutex.
	activeCapture    *capture.Session
	networksDisabled bool

	sleepHandler *sleephandler.SleepHandler

	updateManager *updater.Manager

	jwtCache *jwtCache
}

type oauthAuthFlow struct {
	expiresAt  time.Time
	flow       auth.OAuthFlow
	info       auth.AuthFlowInfo
	waitCancel context.CancelFunc
}

// New server instance constructor.
func New(ctx context.Context, logFile string, configFile string, profilesDisabled bool, updateSettingsDisabled bool, captureEnabled bool, networksDisabled bool) *Server {
	s := &Server{
		rootCtx:                ctx,
		logFile:                logFile,
		persistSyncResponse:    true,
		statusRecorder:         peer.NewRecorder(""),
		profileManager:         profilemanager.NewServiceManager(configFile),
		profilesDisabled:       profilesDisabled,
		updateSettingsDisabled: updateSettingsDisabled,
		captureEnabled:         captureEnabled,
		networksDisabled:       networksDisabled,
		jwtCache:               newJWTCache(),
		extendAuthSessionFlow:  auth.NewPendingFlow(),
		probeThrottle:          newProbeThrottle(probeThreshold),
	}
	agent := &serverAgent{s}
	s.sleepHandler = sleephandler.New(agent)
	s.startSleepDetector()

	return s
}

func (s *Server) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.clientRunning {
		return nil
	}

	state := internal.CtxGetState(s.rootCtx)
	// Every contextState.Set in the connect/login/server paths must push a
	// SubscribeStatus snapshot, otherwise transitions that don't happen to
	// be accompanied by a Mark{Management,Signal,...} call (e.g. plain
	// StatusNeedsLogin after a PermissionDenied login, StatusLoginFailed
	// after OAuth init failure, StatusIdle in the Login defer) leave the
	// UI stuck on the previous status until the next unrelated peer event.
	// Binding the recorder here means new state.Set callsites don't have
	// to opt in individually.
	state.SetOnChange(s.statusRecorder.NotifyStateChange)

	if err := handlePanicLog(); err != nil {
		log.Warnf("failed to redirect stderr: %v", err)
	}

	if err := restoreResidualState(s.rootCtx, s.profileManager.GetStatePath()); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	if s.updateManager == nil {
		stateMgr := statemanager.New(s.profileManager.GetStatePath())
		s.updateManager = updater.NewManager(s.statusRecorder, stateMgr)
		s.updateManager.CheckUpdateSuccess(s.rootCtx)
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
	go s.connectWithRetryRuns(ctx, config, s.statusRecorder, s.clientRunningChan, s.clientGiveUpChan)
	return nil
}

// connectWithRetryRuns runs the client connection with a backoff strategy where we retry the operation as additional
// mechanism to keep the client connected even when the connection is lost.
// we cancel retry if the client receive a stop or down command, or if disable auto connect is configured.
func (s *Server) connectWithRetryRuns(ctx context.Context, profileConfig *profilemanager.Config, statusRecorder *peer.Status, runningChan chan struct{}, giveUpChan chan struct{}) {
	// close(giveUpChan) MUST run on every exit path (DisableAutoConnect
	// return, backoff.Retry return, panic) — Down() blocks for up to 5s
	// waiting on this signal before flipping the state to Idle, and a
	// missed close leaves Down() always hitting the timeout. The signal
	// fires AFTER clientRunning=false is committed under the mutex so a
	// Down/Up racing with the goroutine exit never observes a half-state
	// (chan closed but clientRunning still true).
	defer func() {
		s.mutex.Lock()
		s.clientRunning = false
		s.mutex.Unlock()
		if giveUpChan != nil {
			close(giveUpChan)
		}
	}()

	if s.config.DisableAutoConnect {
		if err := s.connect(ctx, s.config, s.statusRecorder, runningChan); err != nil {
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
		err := s.connect(ctx, profileConfig, statusRecorder, runningChan)
		if err != nil {
			// PermissionDenied means the daemon transitioned to NeedsLogin
			// inside connect(). Without backoff.Permanent the outer retry
			// re-enters connect(), which resets the state to Connecting and
			// makes the tray flicker between NeedsLogin and Connecting until
			// the user logs in. Stop retrying and let the state stick.
			if s, ok := gstatus.FromError(err); ok && s.Code() == codes.PermissionDenied {
				log.Debugf("run client connection exited with PermissionDenied, waiting for login")
				return backoff.Permanent(err)
			}
			log.Debugf("run client connection exited with error: %v. Will retry in the background", err)
			return err
		}

		log.Tracef("client connection exited gracefully, do not need to retry")
		return nil
	}

	if err := backoff.Retry(runOperation, backOff); err != nil {
		log.Errorf("operation failed: %v", err)
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
		config.PreSharedKey = msg.OptionalPreSharedKey
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
	config.DisableIPv6 = msg.DisableIpv6
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

	if err := persistLoginOverrides(activeProf, msg.ManagementUrl, msg.OptionalPreSharedKey); err != nil {
		log.Errorf("failed to persist login overrides: %v", err)
		return nil, fmt.Errorf("persist login overrides: %w", err)
	}

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
				state.Set(internal.StatusNeedsLogin)
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

	// Setup-key path: we are about to dial Management with the key, so the
	// Connecting paint is meaningful here — unlike the SSO branch above,
	// which returns NeedsLogin and parks on the browser leg.
	state.Set(internal.StatusConnecting)

	if loginStatus, err := s.loginAttempt(ctx, msg.SetupKey, ""); err != nil {
		state.Set(loginStatus)
		return nil, err
	}

	return &proto.LoginResponse{}, nil
}

// WaitSSOLogin validates the supplied userCode against the in-flight OAuth
// device/PKCE flow and blocks until the user finishes the browser leg.
//
// The daemon holds StatusNeedsLogin for the whole browser wait (set on
// entry): the login is not done until the token returns, so a client that
// (re)attaches mid-wait — a restarted UI, a second `netbird up` — reads
// "login required" and offers the affordance, instead of a Connecting that
// never resolves. The wait is also tied to the caller's context (see the
// goroutine below), so a client that goes away cancels the wait instead of
// orphaning it on rootCtx until the device-code window expires.
//
// State transitions on exit:
//
//	┌──────────────────────────────────────────┬──────────────────────────────────┐
//	│ Outcome                                  │ contextState                     │
//	├──────────────────────────────────────────┼──────────────────────────────────┤
//	│ Success → loginAttempt ok                │ NeedsLogin held; the caller's Up │
//	│                                          │   drives Connecting → Connected  │
//	│ Success → loginAttempt → still-NeedsLogin│ StatusNeedsLogin (loginAttempt)  │
//	│ Success → loginAttempt error             │ StatusLoginFailed (loginAttempt) │
//	│ UserCode mismatch                        │ StatusLoginFailed                │
//	│ WaitToken: context.Canceled              │ NeedsLogin held. Caller gone     │
//	│   (caller went away — UI restart /       │   (UI/CLI) → a fresh client      │
//	│   Ctrl+C — or internal abort: profile    │   shows the login affordance;    │
//	│   switch / app quit / another            │   internal aborts are            │
//	│   WaitSSOLogin via actCancel/waitCancel) │   overwritten by the next Up.    │
//	│ WaitToken: context.DeadlineExceeded      │ StatusNeedsLogin                 │
//	│   (OAuth device-code window expired      │   (retryable; the UI's "Connect" │
//	│   while waiting on the browser leg)      │   re-enters the Login flow)      │
//	│ WaitToken: any other error               │ StatusLoginFailed                │
//	│   (access_denied, expired_token, HTTP    │   (genuine auth/IO failure;      │
//	│   failure, token validation rejection)   │   surfaced verbatim to caller)   │
//	└──────────────────────────────────────────┴──────────────────────────────────┘
//
// The defer still applies a StatusIdle fallback for the early
// oauth-flow-not-initialized return (before the entry Set), so a half state
// doesn't leak when there is nothing to wait on.
func (s *Server) WaitSSOLogin(callerCtx context.Context, msg *proto.WaitSSOLoginRequest) (*proto.WaitSSOLoginResponse, error) {
	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)

	// Tie the in-flight browser wait to the caller. ctx stays rooted in
	// rootCtx so CtxGetState resolves the daemon's contextState, but if the
	// UI window or CLI that drove the login goes away mid-flow (restart,
	// Ctrl+C) the gRPC callerCtx cancels and we cancel the wait instead of
	// orphaning it on rootCtx until the OAuth device-code window expires.
	// The goroutine exits as soon as either context completes, so it can't
	// outlive the RPC.
	go func() {
		select {
		case <-callerCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

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

	// Hold NeedsLogin for the whole browser wait — the login is not done
	// until the token returns, so a client that (re)attaches mid-wait
	// (restarted UI, second `netbird up`) reads "login required" and offers
	// the affordance instead of a Connecting that never resolves.
	state.Set(internal.StatusNeedsLogin)

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
		switch {
		case errors.Is(err, context.Canceled):
			// External abort. If our caller cancelled (the client closed
			// the browser-login popup, or the UI went away — callerCtx is
			// done), clear the abandoned OAuth flow so a fresh Login starts
			// a new device code instead of reusing this one. The entry
			// NeedsLogin stays in place, so a reattaching client shows the
			// login affordance. An internal abort (actCancel from a new
			// Login/WaitSSOLogin, callerCtx still live) leaves the flow for
			// the new owner — don't clobber it.
			if callerCtx.Err() != nil {
				s.mutex.Lock()
				s.oauthAuthFlow = oauthAuthFlow{}
				s.mutex.Unlock()
			}
		case errors.Is(err, context.DeadlineExceeded):
			// OAuth device-code window expired with no user action.
			// Retryable — leave the daemon in NeedsLogin so the UI
			// keeps the Login affordance instead of reading as a
			// hard failure.
			state.Set(internal.StatusNeedsLogin)
		default:
			state.Set(internal.StatusLoginFailed)
		}
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

	// StatusNeedsLogin is a legitimate fresh-start entry state: a successful
	// WaitSSOLogin deliberately leaves the daemon in NeedsLogin (the login is
	// done, the token is in hand, but the engine hasn't been brought up yet —
	// see WaitSSOLogin's state-transition table). The same holds after a
	// mid-session expiry tore the engine down (clientRunning == false) and the
	// user re-authenticated. In both cases the caller's Up is expected to drive
	// the connection; treat NeedsLogin like Idle and reset to Idle so the
	// engine's own StatusConnecting → StatusConnected progression starts from a
	// clean slate. Without this, the first Up after an SSO login fails with
	// "up already in progress" and the user has to trigger Up a second time
	// (CLI: re-run `netbird up`; GUI: click Connect again).
	if status == internal.StatusNeedsLogin {
		status = internal.StatusIdle
		state.Set(internal.StatusIdle)
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

	go s.connectWithRetryRuns(ctx, s.config, s.statusRecorder, s.clientRunningChan, s.clientGiveUpChan)

	s.mutex.Unlock()
	if msg.GetAsync() {
		return &proto.UpResponse{}, nil
	}
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

	s.mutex.Unlock()

	// Wait for the connectWithRetryRuns goroutine to finish with a short timeout.
	// This prevents the goroutine from setting ErrResetConnection after Down() returns.
	// The giveUpChan is closed by the goroutine's deferred cleanup (see
	// connectWithRetryRuns) on every exit path. A timeout here typically
	// means the goroutine is still wedged inside a slow teardown step.
	if giveUpChan != nil {
		select {
		case <-giveUpChan:
			log.Debugf("client goroutine finished, giveUpChan closed")
		case <-time.After(5 * time.Second):
			log.Warnf("timeout waiting for client goroutine to finish, proceeding anyway")
		}
	}

	// Set Idle only after the retry goroutine has exited (or timed out).
	// Setting it earlier races with the goroutine's own Set(StatusConnecting)
	// at the top of each retry attempt, which would leave the snapshot
	// stuck at Connecting long after the user asked to disconnect.
	internal.CtxGetState(s.rootCtx).Set(internal.StatusIdle)

	// Clear stale management/signal errors so the next Up() (typically for a
	// different profile) starts with a clean status snapshot. Without this,
	// a managementError left over from a LoginFailed cycle persists in the
	// statusRecorder and appears in the new profile's initial
	// SubscribeStatus snapshot, making the new profile look like it also
	// failed to log in.
	s.statusRecorder.MarkManagementDisconnected(nil)
	s.statusRecorder.MarkSignalDisconnected(nil)

	return &proto.DownResponse{}, nil
}

func (s *Server) cleanupConnection() error {
	s.oauthAuthFlow = oauthAuthFlow{}

	if s.actCancel == nil {
		return ErrServiceNotUp
	}

	// Capture the engine reference before cancelling the context.
	// After actCancel(), the connectWithRetryRuns goroutine wakes up
	// and sets connectClient.engine = nil, causing connectClient.Stop()
	// to skip the engine shutdown entirely.
	var engine *internal.Engine
	if s.connectClient != nil {
		engine = s.connectClient.Engine()
	}

	s.actCancel()

	if s.connectClient == nil {
		return nil
	}

	if engine != nil {
		if err := engine.Stop(); err != nil {
			return err
		}
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

// getConfig reads config file and returns Config and whether the config file already existed. Errors out if it does not exist
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

	return s.buildStatusResponse(ctx, msg)
}

// buildStatusResponse composes a StatusResponse from the current daemon
// state. Shared between the unary Status RPC and the SubscribeStatus
// stream so both paths return identical snapshots. ctx scopes the health
// probe runProbes may trigger — a caller that disconnects cancels it.
func (s *Server) buildStatusResponse(ctx context.Context, msg *proto.StatusRequest) (*proto.StatusResponse, error) {
	state := internal.CtxGetState(s.rootCtx)
	status, err := state.Status()
	if err != nil {
		// state.Status() blanks the status when err is set (e.g. management
		// retry loop wrapped a connection error). The underlying status is
		// still meaningful and the failure is already surfaced via
		// FullStatus.ManagementState.Error, so don't propagate err — that
		// would tear down the SubscribeStatus stream and cause the UI to
		// mark the daemon as unreachable on every retry.
		status = state.CurrentStatus()
	}

	if status == internal.StatusNeedsLogin && s.isSessionActive.Load() {
		log.Debug("status requested while session is active, returning SessionExpired")
		status = internal.StatusSessionExpired
		s.isSessionActive.Store(false)
	}

	statusResponse := proto.StatusResponse{Status: string(status), DaemonVersion: version.NetbirdVersion()}

	if deadline := s.statusRecorder.GetSessionExpiresAt(); !deadline.IsZero() {
		statusResponse.SessionExpiresAt = timestamppb.New(deadline)
	}

	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)

	if msg.GetFullPeerStatus {
		s.runProbes(ctx, msg.ShouldRunProbes)
		fullStatus := s.statusRecorder.GetFullStatus()
		pbFullStatus := fullStatus.ToProto()
		pbFullStatus.Events = s.statusRecorder.GetEventHistory()
		pbFullStatus.SshServerState = s.getSSHServerState()
		pbFullStatus.NetworksRevision = s.statusRecorder.GetNetworksRevision()
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

// RequestExtendAuthSession initiates the SSO session-extension flow and
// returns the verification URI the UI should open. The flow state is held
// in s.extendAuthSessionFlow until WaitExtendAuthSession resolves it.
func (s *Server) RequestExtendAuthSession(
	ctx context.Context,
	msg *proto.RequestExtendAuthSessionRequest,
) (*proto.RequestExtendAuthSessionResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	s.mutex.Lock()
	config := s.config
	connectClient := s.connectClient
	s.mutex.Unlock()

	if config == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not configured")
	}
	if connectClient == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not running")
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

	s.extendAuthSessionFlow.Set(oAuthFlow, authInfo)

	return &proto.RequestExtendAuthSessionResponse{
		VerificationURI:         authInfo.VerificationURI,
		VerificationURIComplete: authInfo.VerificationURIComplete,
		UserCode:                authInfo.UserCode,
		DeviceCode:              authInfo.DeviceCode,
		ExpiresIn:               int64(authInfo.ExpiresIn),
	}, nil
}

// WaitExtendAuthSession blocks until the user completes the SSO step
// initiated by RequestExtendAuthSession, then forwards the resulting JWT
// to the management server's ExtendAuthSession RPC. The returned deadline
// is also applied locally via the engine so SubscribeStatus consumers see
// the refreshed state.
func (s *Server) WaitExtendAuthSession(
	ctx context.Context,
	req *proto.WaitExtendAuthSessionRequest,
) (*proto.WaitExtendAuthSessionResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	oAuthFlow, authInfo, ok := s.extendAuthSessionFlow.Get()

	s.mutex.Lock()
	connectClient := s.connectClient
	s.mutex.Unlock()

	if !ok || authInfo.DeviceCode != req.DeviceCode {
		return nil, gstatus.Errorf(codes.InvalidArgument, "invalid device code or no active extend-session flow")
	}

	// Preempt a previous WaitExtendAuthSession (e.g. when the tray
	// notification and the about-to-expire dialog both start a flow on
	// the same deadline). The older waiter exits via context.Canceled;
	// the new one takes over the IdP poll.
	s.extendAuthSessionFlow.CancelWait()

	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.extendAuthSessionFlow.SetWaitCancel(cancel)

	tokenInfo, err := oAuthFlow.WaitToken(waitCtx, authInfo)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, gstatus.Errorf(codes.Canceled, "extend-session flow preempted")
		}
		return nil, gstatus.Errorf(codes.Internal, "failed to obtain JWT token: %v", err)
	}

	// Clear pending flow before talking to mgm so a retry can re-initiate.
	s.extendAuthSessionFlow.Clear()

	if connectClient == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not running")
	}
	engine := connectClient.Engine()
	if engine == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "engine is not initialised")
	}

	deadline, err := engine.ExtendAuthSession(ctx, tokenInfo.GetTokenToUse())
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "management ExtendAuthSession failed: %v", err)
	}

	resp := &proto.WaitExtendAuthSessionResponse{}
	if !deadline.IsZero() {
		resp.SessionExpiresAt = timestamppb.New(deadline)
	}
	return resp, nil
}

// DismissSessionWarning forwards the user's "Dismiss" click on the
// T-WarningLead notification down to the engine's sessionWatcher so the
// T-FinalWarningLead fallback is suppressed for the current deadline.
// Best-effort: when the client/engine is not yet running the call is a
// successful no-op (the watcher has no deadline to dismiss anyway).
func (s *Server) DismissSessionWarning(
	_ context.Context,
	_ *proto.DismissSessionWarningRequest,
) (*proto.DismissSessionWarningResponse, error) {
	s.mutex.Lock()
	connectClient := s.connectClient
	s.mutex.Unlock()
	if connectClient == nil {
		return &proto.DismissSessionWarningResponse{}, nil
	}
	if engine := connectClient.Engine(); engine != nil {
		engine.DismissSessionWarning()
	}
	return &proto.DismissSessionWarningResponse{}, nil
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

	if engine.IsBlockInbound() {
		return gstatus.Errorf(codes.FailedPrecondition, "expose requires inbound connections but 'block inbound' is enabled, disable it first")
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
				ServiceName:      result.ServiceName,
				ServiceUrl:       result.ServiceURL,
				Domain:           result.Domain,
				PortAutoAssigned: result.PortAutoAssigned,
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

func (s *Server) runProbes(ctx context.Context, waitForProbeResult bool) {
	if s.connectClient == nil {
		return
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return
	}

	s.probeThrottle.Run(ctx, engine, s.statusRecorder, waitForProbeResult)
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
	disableIPv6 := cfg.DisableIPv6
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
		DisableIpv6:                   disableIPv6,
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
		DisableNetworks:       s.networksDisabled,
	}

	return features, nil
}

func (s *Server) connect(ctx context.Context, config *profilemanager.Config, statusRecorder *peer.Status, runningChan chan struct{}) error {
	log.Tracef("running client connection")
	client := internal.NewConnectClient(ctx, config, statusRecorder)
	client.SetUpdateManager(s.updateManager)
	client.SetSyncResponsePersistence(s.persistSyncResponse)

	s.mutex.Lock()
	s.connectClient = client
	s.mutex.Unlock()

	if err := client.Run(runningChan, s.logFile); err != nil {
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

func (s *Server) startUpdateManagerForGUI() {
	if s.updateManager == nil {
		return
	}
	s.updateManager.Start(s.rootCtx)
	s.updateManager.NotifyUI()
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

// persistLoginOverrides writes management URL and pre-shared key from a LoginRequest to the
// active profile config so that subsequent reads pick them up. Empty/nil values are ignored.
func persistLoginOverrides(activeProf *profilemanager.ActiveProfileState, managementURL string, preSharedKey *string) error {
	if preSharedKey != nil && *preSharedKey == "" {
		preSharedKey = nil
	}
	if managementURL == "" && preSharedKey == nil {
		return nil
	}

	cfgPath, err := activeProf.FilePath()
	if err != nil {
		return fmt.Errorf("active profile file path: %w", err)
	}

	input := profilemanager.ConfigInput{
		ConfigPath:    cfgPath,
		ManagementURL: managementURL,
		PreSharedKey:  preSharedKey,
	}
	if _, err := profilemanager.UpdateOrCreateConfig(input); err != nil {
		return fmt.Errorf("update config: %w", err)
	}
	return nil
}
