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
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netbirdio/netbird/client/internal/localmetrics"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	sleephandler "github.com/netbirdio/netbird/client/internal/sleep/handler"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/updater"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
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

	// uiLogPath is the desktop UI's absolute log path, reported via
	// RegisterUILog. Guarded by mutex. Consumed by DebugBundle so the bundle
	// can collect the GUI log even though the daemon runs as root and can't
	// resolve the user's config dir. Last-writer-wins (one UI per socket).
	// DebugBundle opens it on behalf of the bundle requester and refuses a file
	// that caller does not own, so a local user cannot read another user's log
	// or a root-only file through it.
	uiLogPath string

	oauthAuthFlow oauthAuthFlow
	// extendAuthSessionFlow holds the pending PKCE flow created by
	// RequestExtendAuthSession until WaitExtendAuthSession resolves it.
	// Kept separate from oauthAuthFlow (which is reserved for the SSH
	// JWT path) so a concurrent SSH auth doesn't clobber the session
	// extend flow or vice versa.
	extendAuthSessionFlow *auth.PendingFlow

	// guardedConfigMu serializes a privilege check against the write it
	// authorizes. Without it the two are separate steps over the same file, and a
	// change that was allowed because the profile had the SSH server disabled
	// could land after a concurrent privileged request enabled it.
	guardedConfigMu sync.Mutex

	mutex  sync.Mutex
	config *profilemanager.Config
	proto.UnimplementedDaemonServiceServer
	// clientRunning tracks "the daemon wants to be connected" — set true by
	// Start / Up, cleared by Down / Logout. Persists across retry
	// loops, signal disconnects, and ErrResetConnection cycles. NOT
	// changed by connectWithRetryRuns goroutine exit — for that
	// (goroutine-still-alive) check, see connectionGoroutineRunning() which
	// derives from clientGiveUpChan close state. Protected by s.mutex.
	clientRunning     bool
	clientRunningChan chan struct{}
	clientGiveUpChan  chan struct{} // closed when connectWithRetryRuns goroutine exits

	connectClient *internal.ConnectClient

	statusRecorder *peer.Status
	sessionWatcher *internal.SessionWatcher
	localMetrics   *localmetrics.Manager

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

	// mdmTicker periodically re-reads the OS-native MDM policy and triggers
	// an engine restart when the policy changes. Launched once by Start;
	// stopped by the rootCtx cancellation.
	mdmTicker *mdm.Ticker

	updateManager *updater.Manager

	jwtCache *jwtCache

	// loginAttemptFn stands in for the Management login round trip. Tests set
	// it to drive the login outcomes that need a server on the other end;
	// production leaves it nil, and every login goes through loginAttempt.
	loginAttemptFn func(ctx context.Context, setupKey, jwtToken string) (internal.StatusType, error)

	isLoginRequiredFn func(ctx context.Context) (bool, error)
}

type oauthAuthFlow struct {
	expiresAt time.Time
	flow      auth.OAuthFlow
	info      auth.AuthFlowInfo

	// cacheGeneration is the SSH JWT cache's generation as of the start of the
	// request that created this flow. The flow outlives a profile switch, so
	// reading the generation any later — when the IdP has answered, or when the
	// token finally arrives — would read the new session's one and let the old
	// session's token into the new session's cache.
	cacheGeneration uint64

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

	s.localMetrics = localmetrics.NewManager(ctx, s.statusRecorder, s.clientMetricsGatherer)

	return s
}

// clientMetricsGatherer returns the Prometheus gatherer of the running
// engine's client metrics, or nil when no engine is running.
func (s *Server) clientMetricsGatherer() prometheus.Gatherer {
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
	return engine.GetClientMetrics().PrometheusGatherer()
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

	if err := RestoreResidualState(s.rootCtx, s.profileManager.GetStatePath()); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	if s.updateManager == nil {
		stateMgr := statemanager.New(s.profileManager.GetStatePath())
		s.updateManager = updater.NewManager(s.statusRecorder, stateMgr)
		s.updateManager.CheckUpdateSuccess(s.rootCtx)
	}

	// MDM policy reload ticker: every minute the desktop daemon re-reads
	// the OS-native managed-config store and, on diff vs the previous
	// observation, cancels the active engine context so connectWithRetry-
	// Runs re-resolves Config (re-running profilemanager.Config.apply which
	// applies the freshly-read MDM policy as the last layer) and brings
	// the engine back with the new values.
	if s.mdmTicker == nil {
		s.mdmTicker = mdm.NewTicker(mdm.DefaultReloadInterval)
		go s.mdmTicker.Run(s.rootCtx, s.onMDMPolicyChange)
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
	s.localMetrics.Reconcile(config.LocalMetricsEnabled, config.LocalMetricsAddress)

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
	s.publishConfigChangedEvent(proto.MetadataSourceStartup)
	return nil
}

// connectWithRetryRuns runs the client connection with a backoff strategy where we retry the operation as additional
// mechanism to keep the client connected even when the connection is lost.
// we cancel retry if the client receive a stop or down command, or if disable auto connect is configured.
//
// The goroutine's exit is signalled to the daemon via close(giveUpChan)
// — placed in the function-scope defer so every return path (panic,
// DisableAutoConnect early-exit, backoff exhausted, ctx cancel) closes
// it. Callers that need to observe "is the goroutine still alive?" use
// Server.connectionGoroutineRunning() which non-blockingly checks the close state
// of clientGiveUpChan. The defer does NOT touch s.mutex; the daemon's
// "intent" (clientRunning) is maintained by the RPC handlers, not by this
// goroutine.
func (s *Server) connectWithRetryRuns(ctx context.Context, profileConfig *profilemanager.Config, statusRecorder *peer.Status, runningChan chan struct{}, giveUpChan chan struct{}) {
	// close(giveUpChan) MUST run on every exit path (DisableAutoConnect
	// return, backoff.Retry return, panic) — Down() blocks for up to 5s
	// waiting on this signal before flipping the state to Idle, and a
	// missed close leaves Down() always hitting the timeout.
	defer func() {
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
	// giveUpChan is closed by the function-scope defer.
}

// connectionGoroutineRunning reports whether the connectWithRetryRuns goroutine is
// still running. Returns false when no goroutine has ever been started
// AND when the most recent one has already closed clientGiveUpChan on
// exit (whether due to ctx cancel, DisableAutoConnect single-shot
// completion, or backoff retry exhaustion).
//
// MUST be called with s.mutex held — accesses s.clientGiveUpChan which
// is written by Start/Up under the same lock.
func (s *Server) connectionGoroutineRunning() bool {
	if s.clientGiveUpChan == nil {
		return false
	}
	select {
	case <-s.clientGiveUpChan:
		return false
	default:
		return true
	}
}

// attemptLogin runs a login round trip against Management, or the stand-in a
// test installed in place of it.
func (s *Server) attemptLogin(ctx context.Context, setupKey, jwtToken string) (internal.StatusType, error) {
	if s.loginAttemptFn != nil {
		return s.loginAttemptFn(ctx, setupKey, jwtToken)
	}
	return s.loginAttempt(ctx, setupKey, jwtToken)
}

func (s *Server) isLoginRequired(ctx context.Context) (bool, error) {
	if s.isLoginRequiredFn != nil {
		return s.isLoginRequiredFn(ctx)
	}

	authClient, err := auth.NewAuth(ctx, s.config.PrivateKey, s.config.ManagementURL, s.config)
	if err != nil {
		log.Errorf("failed to create auth client: %v", err)
		return false, err
	}
	defer authClient.Close()

	return authClient.IsLoginRequired(ctx)
}

// loginAttempt attempts to login using the provided information. It returns
// StatusNeedsLogin when Management refused the peer's credentials and
// StatusLoginFailed for every other failure, so callers can tell an
// authentication decision apart from a login that never got made.
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
	// Privilege gate: refuse the parts of the request that would let a local
	// user turn the root daemon into a root shell. Held across the write so the
	// config cannot gain the SSH server between the decision and the update.
	//
	// Taken before s.mutex: authorizeAndPrepareLogin takes s.mutex while holding
	// guardedConfigMu, so acquiring the two in the other order here would let a
	// concurrent login deadlock the daemon.
	s.guardedConfigMu.Lock()
	defer s.guardedConfigMu.Unlock()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Skip the update-settings gate when the request carries no actual
	// overrides: the CLI builds a SetConfigRequest unconditionally on
	// every `netbird up` (setupSetConfigReq in cmd/up.go), so a plain
	// `netbird up` would otherwise always trip the gate and surface a
	// misleading "setConfig method is not available" warning, even when
	// the user did not pass any config flag.
	if setConfigRequestHasConfigOverrides(msg) {
		if s.checkUpdateSettingsDisabled() {
			return nil, gstatus.Errorf(codes.Unavailable, errUpdateSettingsDisabled)
		}
	}

	// MDM gate: refuse the whole request if any of its fields is enforced
	// by the active MDM policy. The error carries an MDMManagedFields-
	// Violation detail listing the offending key names. Non-conflicting
	// fields in the same request are not applied either.
	policy := loadMDMPolicy()
	if err := rejectMDMManagedFieldConflicts(mdmManagedFieldConflicts(msg, policy)); err != nil {
		return nil, err
	}

	stored, err := s.storedProfileConfig(msg.ProfileName, msg.Username)
	if err != nil {
		return nil, err
	}
	if err := requirePrivilegeForConfigChange(callerCtx, stored, privilegedChangeFromSetConfig(msg)); err != nil {
		return nil, err
	}

	config, err := s.setConfigInputFromRequest(msg)
	if err != nil {
		return nil, err
	}

	updatedConf, err := profilemanager.UpdateConfig(config)
	if err != nil {
		log.Errorf("failed to update profile config: %v", err)
		return nil, fmt.Errorf("failed to update profile config: %w", err)
	}

	if activeProf, err := s.profileManager.GetActiveProfileState(); err == nil {
		if activePath, err := activeProf.FilePath(); err == nil && activePath == config.ConfigPath {
			s.localMetrics.Reconcile(updatedConf.LocalMetricsEnabled, updatedConf.LocalMetricsAddress)
		}
	}

	return &proto.SetConfigResponse{}, nil
}

// setConfigInputFromRequest translates a SetConfigRequest into the
// profilemanager.ConfigInput that profilemanager.UpdateConfig consumes.
// Pure mapping with no business logic beyond presence-aware copying of
// optional fields and the "empty / clean" semantics for the two slice
// fields (DNS labels, NAT external IPs). Extracted from SetConfig to
// keep the handler's cognitive complexity below the SonarCube
// threshold; the body is intentionally linear because each proto
// field is its own optional case. Returns the resolved ConfigInput
// and a non-nil error only when the active profile file path cannot
// be determined.
func (s *Server) setConfigInputFromRequest(msg *proto.SetConfigRequest) (profilemanager.ConfigInput, error) {
	var config profilemanager.ConfigInput

	resolved, err := s.resolveProfileHandle(msg.ProfileName, msg.Username)
	if err != nil {
		log.Errorf("failed to resolve profile %q: %v", msg.ProfileName, err)
		return config, err
	}
	profPath := resolved.Path
	if profPath == "" {
		profPath = profilemanager.DefaultConfigPath
	}
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
		config.DNSLabels = domain.FromPunycodeList(msg.DnsLabels)
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
	config.LocalMetricsEnabled = msg.EnableLocalMetrics
	config.LocalMetricsAddress = msg.LocalMetricsAddress
	config.DisableAutoConnect = msg.DisableAutoConnect
	config.ServerSSHAllowed = msg.ServerSSHAllowed
	config.RemoteJobsAllowed = msg.RemoteJobsAllowed
	config.NetworkMonitor = msg.NetworkMonitor
	config.DisableClientRoutes = msg.DisableClientRoutes
	config.DisableServerRoutes = msg.DisableServerRoutes
	config.DisableDNS = msg.DisableDns
	config.DisableFirewall = msg.DisableFirewall
	config.BlockLANAccess = msg.BlockLanAccess
	config.DisableNotifications = msg.DisableNotifications
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
	return config, nil
}

// Login uses setup key to prepare configuration for the daemon.
func (s *Server) Login(callerCtx context.Context, msg *proto.LoginRequest) (*proto.LoginResponse, error) {
	// Config-override gates. LoginRequest carries the same surface as
	// SetConfigRequest (managementUrl, PSK, ssh/rosenpass/port toggles,
	// ...), so the same protections must apply. Without these the CLI
	// command `netbird up --management-url=X` (which falls through to
	// Login when SetConfig is rejected — see cmd/up.go) would silently
	// bypass `--disable-update-settings` and any MDM policy.
	if loginRequestHasConfigOverrides(msg) {
		if s.checkUpdateSettingsDisabled() {
			return nil, gstatus.Errorf(codes.Unavailable, errUpdateSettingsDisabled)
		}
		policy := loadMDMPolicy()
		if err := rejectMDMManagedFieldConflicts(loginRequestMDMConflicts(msg, policy)); err != nil {
			return nil, err
		}
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	// Privilege gate: same restrictions as SetConfig, since LoginRequest can carry
	// the same fields. It runs before anything here changes daemon state, so a
	// refused login neither switches the profile nor cancels a login already in
	// progress, and it reads the profile the request targets, which is the one the
	// switch below would activate.
	stored, err := s.storedLoginConfig(activeProf, msg)
	if err != nil {
		return nil, err
	}
	if err := requirePrivilegeForConfigChange(callerCtx, stored, privilegedChangeFromLogin(msg)); err != nil {
		return nil, err
	}

	state := internal.CtxGetState(s.rootCtx)
	status := state.CurrentStatus()
	if status == internal.StatusConnected {
		return &proto.LoginResponse{}, nil
	}

	defer func() {
		status, err := state.Status()
		if err != nil || (status != internal.StatusNeedsLogin && status != internal.StatusLoginFailed) {
			state.Set(internal.StatusIdle)
		}
	}()

	ctx, activeProf, err := s.authorizeAndPrepareLogin(callerCtx, msg, activeProf)
	if err != nil {
		// The RPC boundary is where this gets recorded: nothing logs handler
		// errors for us, and a caller that retries would otherwise leave no
		// trace in the daemon log. A refusal is skipped because the gate has
		// already logged the decision, with the caller's identity.
		if gstatus.Code(err) != codes.PermissionDenied {
			log.Errorf("failed to prepare login: %v", err)
		}
		return nil, err
	}

	log.Infof("active profile: %s for %s", activeProf.ID, activeProf.Username)

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

	s.localMetrics.Reconcile(config.LocalMetricsEnabled, config.LocalMetricsAddress)

	// A probe that errors leaves the login undecided: Management unreachable, a
	// restart mid-request, an internal error. Those are returned for the caller
	// to retry, because turning them into an SSO prompt asks the user to solve
	// something that is not theirs to solve, and a browser login cannot succeed
	// while Management is unreachable anyway. Only Management refusing the
	// peer's key is a decision, and IsLoginRequired reports that as
	// needsLogin=true rather than an error.
	needsLogin, err := s.isLoginRequired(ctx)
	if err != nil {
		state.Set(internal.StatusLoginFailed)
		return nil, err
	}
	if !needsLogin {
		state.Set(internal.StatusIdle)
		return &proto.LoginResponse{}, nil
	}

	if msg.SetupKey == "" {
		return s.beginSSOLogin(ctx, config, msg)
	}

	// Setup-key path: we are about to dial Management with the key, so the
	// Connecting paint is meaningful here — unlike the SSO branch above,
	// which returns NeedsLogin and parks on the browser leg.
	state.Set(internal.StatusConnecting)

	if loginStatus, err := s.attemptLogin(ctx, msg.SetupKey, ""); err != nil {
		state.Set(loginStatus)
		return nil, err
	}

	return &proto.LoginResponse{}, nil
}

// beginSSOLogin starts the browser leg of a login that carries no setup key and
// returns the response that parks the caller on it.
func (s *Server) beginSSOLogin(ctx context.Context, config *profilemanager.Config, msg *proto.LoginRequest) (*proto.LoginResponse, error) {
	state := internal.CtxGetState(s.rootCtx)

	hint := ""
	if msg.Hint != nil {
		hint = *msg.Hint
	}
	oAuthFlow, err := auth.NewOAuthFlow(ctx, config, msg.IsUnixDesktopClient, false, hint)
	if err != nil {
		state.Set(internal.StatusLoginFailed)
		return nil, err
	}

	if resp := s.pendingOAuthFlowResponse(ctx, oAuthFlow); resp != nil {
		state.Set(internal.StatusNeedsLogin)
		return resp, nil
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

// pendingOAuthFlowResponse returns the in-flight flow's response when it
// targets the same IdP client and has enough time left for the user to finish
// the browser leg, so a second login joins the pending flow instead of opening
// a competing one. A flow too close to expiry has its waiter cancelled and nil
// returned, leaving the caller to start a fresh flow.
func (s *Server) pendingOAuthFlowResponse(ctx context.Context, oAuthFlow auth.OAuthFlow) *proto.LoginResponse {
	if s.oauthAuthFlow.flow == nil || s.oauthAuthFlow.flow.GetClientID(ctx) != oAuthFlow.GetClientID(ctx) {
		return nil
	}

	if s.oauthAuthFlow.expiresAt.After(time.Now().Add(90 * time.Second)) {
		log.Debugf("using previous oauth flow info")
		return &proto.LoginResponse{
			NeedsSSOLogin:           true,
			VerificationURI:         s.oauthAuthFlow.info.VerificationURI,
			VerificationURIComplete: s.oauthAuthFlow.info.VerificationURIComplete,
			UserCode:                s.oauthAuthFlow.info.UserCode,
		}
	}

	log.Warnf("canceling previous waiting execution")
	if s.oauthAuthFlow.waitCancel != nil {
		s.oauthAuthFlow.waitCancel()
	}

	return nil
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

	if loginStatus, err := s.attemptLogin(ctx, "", tokenInfo.GetTokenToUse()); err != nil {
		state.Set(loginStatus)
		return nil, err
	}

	log.Infof("SSO login flow finished, returning success to caller")
	return &proto.WaitSSOLoginResponse{
		Email: tokenInfo.Email,
	}, nil
}

// Up starts engine work in the daemon.
func (s *Server) Up(callerCtx context.Context, msg *proto.UpRequest) (*proto.UpResponse, error) {
	log.Infof("up request received")
	s.mutex.Lock()
	// clientRunning is the daemon-intent flag (set by previous Up/Start, cleared
	// by Down). connectionGoroutineRunning() reports whether the previous retry-loop
	// goroutine is still trying. When intent is up AND goroutine is alive,
	// the existing engine is on the job — just wait for it. When intent
	// is up but the goroutine has given up (backoff exhausted) OR when
	// intent is down, fall through to spawn a fresh retry loop.
	if s.clientRunning && s.connectionGoroutineRunning() {
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
	if err := RestoreResidualState(callerCtx, s.profileManager.GetStatePath()); err != nil {
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
		if _, err := s.switchProfileIfNeeded(*msg.ProfileName, msg.Username, activeProf); err != nil {
			s.mutex.Unlock()
			log.Errorf("failed to switch profile: %v", err)
			return nil, err
		}
	}

	activeProf, err = s.profileManager.GetActiveProfileState()
	if err != nil {
		s.mutex.Unlock()
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	log.Infof("active profile: %s for %s", activeProf.ID, activeProf.Username)

	config, _, err := s.getConfig(activeProf)
	if err != nil {
		s.mutex.Unlock()
		log.Errorf("failed to get active profile config: %v", err)
		return nil, fmt.Errorf("failed to get active profile config: %w", err)
	}
	s.config = config

	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)
	s.localMetrics.Reconcile(s.config.LocalMetricsEnabled, s.config.LocalMetricsAddress)

	s.clientRunning = true
	s.clientRunningChan = make(chan struct{})
	s.clientGiveUpChan = make(chan struct{})

	go s.connectWithRetryRuns(ctx, s.config, s.statusRecorder, s.clientRunningChan, s.clientGiveUpChan)
	s.publishConfigChangedEvent(proto.MetadataSourceUpRPC)

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

// storedProfileConfig loads the on-disk config of the profile a request
// targets, so a privileged-change decision can be made against the values the
// profile currently holds. A profile that has no config file yet yields nil,
// which every caller must read as "nothing enabled yet".
func (s *Server) storedProfileConfig(handle, username string) (*profilemanager.Config, error) {
	resolved, err := s.resolveProfileHandle(handle, username)
	if err != nil {
		return nil, err
	}

	path := resolved.Path
	if path == "" {
		path = profilemanager.DefaultConfigPath
	}

	return s.storedConfigAtPath(path)
}

// storedLoginConfig loads the on-disk config of the profile a login request
// targets: the one it names, or the active one when it names none. Used to decide
// a privileged change before the request is allowed to switch profiles.
func (s *Server) storedLoginConfig(activeProf *profilemanager.ActiveProfileState, msg *proto.LoginRequest) (*profilemanager.Config, error) {
	if msg.ProfileName == nil {
		cfgPath, err := activeProf.FilePath()
		if err != nil {
			return nil, fmt.Errorf("active profile file path: %w", err)
		}
		return s.storedConfigAtPath(cfgPath)
	}

	// Mirrors switchProfileIfNeeded: the default profile resolves without a
	// username, so this reads the same profile the switch would activate.
	handle := *msg.ProfileName
	username := ""
	if handle != profilemanager.DefaultProfileName {
		username = msg.GetUsername()
	}
	return s.storedProfileConfig(handle, username)
}

// storedConfigAtPath reads a profile config file, yielding nil when it does not
// exist yet.
func (s *Server) storedConfigAtPath(path string) (*profilemanager.Config, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil //nolint:nilnil
		}
		return nil, fmt.Errorf("stat profile config: %w", err)
	}

	cfg, err := profilemanager.GetConfig(path)
	if err != nil {
		return nil, fmt.Errorf("read profile config: %w", err)
	}
	return cfg, nil
}

// resolveProfileHandle resolves a wire-level profile handle (display
// name, ID, or unique ID prefix) to a concrete profile. Returns gRPC
// status errors so handlers can return them directly.
func (s *Server) resolveProfileHandle(handle, username string) (*profilemanager.Profile, error) {
	p, err := s.profileManager.ResolveProfile(handle, username)
	if err == nil {
		return p, nil
	}
	var amb *profilemanager.ErrAmbiguousHandle
	if errors.As(err, &amb) {
		return nil, gstatus.Errorf(codes.InvalidArgument, "%v", amb)
	}
	if errors.Is(err, profilemanager.ErrProfileNotFound) {
		return nil, gstatus.Errorf(codes.NotFound, "profile %q not found", handle)
	}
	return nil, fmt.Errorf("resolve profile: %w", err)
}

// switchProfileIfNeeded resolves the user-supplied handle, updates the
// active profile state if it differs from the current one, and returns
// the resolved profile so callers can include its ID in RPC responses.
func (s *Server) switchProfileIfNeeded(handle string, userName *string, activeProf *profilemanager.ActiveProfileState) (*profilemanager.Profile, error) {
	if handle != profilemanager.DefaultProfileName && (userName == nil || *userName == "") {
		log.Errorf("profile name is set to %s, but username is not provided", handle)
		return nil, fmt.Errorf("profile name is set to %s, but username is not provided", handle)
	}

	var username string
	if handle != profilemanager.DefaultProfileName {
		username = *userName
	}

	resolved, err := s.resolveProfileHandle(handle, username)
	if err != nil {
		return nil, err
	}

	if resolved.ID != activeProf.ID || username != activeProf.Username {
		if s.checkProfilesDisabled() {
			log.Errorf("profiles are disabled, you cannot use this feature without profiles enabled")
			return nil, gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
		}

		log.Infof("switching to profile %s (%s) for user %s", resolved.Name, resolved.ID, username)
		if err := s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			ID:       resolved.ID,
			Username: username,
		}); err != nil {
			log.Errorf("failed to set active profile state: %v", err)
			return nil, fmt.Errorf("failed to set active profile state: %w", err)
		}
	}

	return resolved, nil
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
		if _, err := s.switchProfileIfNeeded(*msg.ProfileName, msg.Username, activeProf); err != nil {
			log.Errorf("failed to switch profile: %v", err)
			return nil, err
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
	s.localMetrics.Reconcile(config.LocalMetricsEnabled, config.LocalMetricsAddress)

	s.jwtCache.clear()

	if msg != nil && msg.ProfileName != nil {
		s.publishProfileListChanged(*msg.ProfileName)
	}

	return &proto.SwitchProfileResponse{Id: activeProf.ID.String()}, nil
}

// Down engine work in the daemon.
func (s *Server) Down(ctx context.Context, _ *proto.DownRequest) (*proto.DownResponse, error) {
	s.mutex.Lock()

	giveUpChan := s.clientGiveUpChan

	if err := s.cleanupConnection(); err != nil {
		s.mutex.Unlock()
		if errors.Is(err, ErrServiceNotUp) {
			log.Debugf("Down called while service not up: %v", err)
			return nil, err
		}
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

	// Daemon intent flips to "down" — all callers (Down RPC,
	// Logout RPC handlers) tear down the connection because the user
	// explicitly asked for it. MDM restart does NOT go through this
	// path, so its clientRunning stays true.
	s.clientRunning = false

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

	// TODO: consider calling s.connectClient.Stop() instead of engine.Stop().
	// actCancel() lets the run loop stop the engine too, so both stop it
	// concurrently; ConnectClient.Stop cancels and waits for the run loop,
	// making the run loop the sole owner of engine shutdown.
	if engine != nil {
		if err := engine.Stop(); err != nil {
			log.Errorf("failed to stop engine during cleanup: %v", err)
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
	if msg.Username == nil || *msg.Username == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "username must be provided when profile name is specified")
	}
	username := *msg.Username

	resolved, err := s.resolveProfileHandle(*msg.ProfileName, username)
	if err != nil {
		return nil, err
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "failed to get active profile state: %v", err)
	}

	if err := s.validateProfileLogout(resolved.ID, isActiveProfile(activeProf, resolved.ID, username)); err != nil {
		return nil, err
	}

	if err := s.logoutFromProfile(ctx, resolved, username); err != nil {
		log.Errorf("failed to logout from profile %s: %v", resolved.ID, err)
		// A refused deregistration is already a status error carrying the reason
		// and the command to run; rewrapping it as Internal would flatten both
		// into a gRPC dump for the user.
		if _, isStatus := gstatus.FromError(err); isStatus {
			return nil, err
		}
		return nil, gstatus.Errorf(codes.Internal, "logout: %v", err)
	}

	s.cleanupAfterProfileLogout(resolved.ID, username)

	return &proto.LogoutResponse{}, nil
}

// cleanupAfterProfileLogout tears the connection down and asks for a new login
// when the profile that was just deregistered is the one the daemon is running.
// The active profile is read again here rather than reused from the pre-flight
// check: Login switches profiles under guardedConfigMu, which this path does not
// hold, so a login that landed meanwhile must not have its fresh connection
// dropped by a logout that targeted the profile it replaced.
func (s *Server) cleanupAfterProfileLogout(id profilemanager.ID, username string) {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state after logout from profile %s: %v", id, err)
		return
	}

	if !isActiveProfile(activeProf, id, username) {
		return
	}

	if err := s.cleanupConnection(); err != nil && !errors.Is(err, ErrServiceNotUp) {
		log.Errorf("failed to cleanup connection: %v", err)
	}
	s.jwtCache.clear()
	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusNeedsLogin)
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
	s.jwtCache.clear()

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

// validateProfileLogout gates a profile-addressed logout. Deregistering the
// profile the daemon already runs is what a plain `netbird logout` does, so the
// profiles-disabled kill switch must not block it. Logging out of any other
// profile is profile management and stays gated.
func (s *Server) validateProfileLogout(id profilemanager.ID, isActive bool) error {
	if id == "" {
		return gstatus.Errorf(codes.InvalidArgument, "profile name must be provided")
	}

	if isActive {
		return nil
	}

	if s.checkProfilesDisabled() {
		return gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
	}

	return nil
}

// isActiveProfile reports whether id is the profile the daemon runs for
// username. The username is part of the comparison because legacy profile IDs
// are display names, which two users can both hold; the default profile is
// shared by every user and carries no username.
func isActiveProfile(activeProf *profilemanager.ActiveProfileState, id profilemanager.ID, username string) bool {
	if activeProf == nil || activeProf.ID != id {
		return false
	}

	return id == profilemanager.DefaultProfileName || activeProf.Username == username
}

// logoutFromProfile deregisters profile, reusing the running config when
// profile is the one the daemon is connected with. The username takes part in
// that decision for the same reason it does in the logout gate: a legacy
// profile ID is a display name two users can share, and sending the running
// config for a namesake would deregister the active peer instead of the
// requested one.
func (s *Server) logoutFromProfile(ctx context.Context, profile *profilemanager.Profile, username string) error {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err == nil && isActiveProfile(activeProf, profile.ID, username) && s.connectClient != nil {
		return s.sendLogoutRequest(ctx)
	}

	cfgPath := profile.Path
	if cfgPath == "" {
		cfgPath = profilemanager.DefaultConfigPath
	}

	config, err := profilemanager.GetConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("profile '%s' not found", profile.ID)
	}

	return s.sendLogoutRequestWithConfig(ctx, config)
}

func (s *Server) sendLogoutRequest(ctx context.Context) error {
	return s.sendLogoutRequestWithConfig(ctx, s.config)
}

func (s *Server) sendLogoutRequestWithConfig(ctx context.Context, config *profilemanager.Config) error {
	// Privilege gate: deregistering frees this machine's key to be registered
	// against another management server, which is only restricted while the SSH
	// server makes that a privilege handover.
	if err := requirePrivilegeForDeregistration(ctx, config); err != nil {
		return err
	}

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

	if err := mgmClient.Logout(); err != nil {
		// The peer is already gone from the management server (e.g. deleted
		// from the dashboard). The logout's goal — deregistering this peer —
		// is therefore already satisfied, so treat NotFound as success rather
		// than blocking the logout/profile-removal flow.
		if logoutPeerGone(err) {
			log.Infof("peer already removed from management server, treating logout as successful")
			return nil
		}
		return err
	}

	return nil
}

// Status returns the daemon status
func (s *Server) Status(
	ctx context.Context,
	msg *proto.StatusRequest,
) (*proto.StatusResponse, error) {
	s.mutex.Lock()
	// Only wait if the retry-loop goroutine is alive and making
	// progress. clientRunning=true with connectionGoroutineRunning=false means the
	// backoff has given up — there is nothing to wait for; let the
	// caller observe the failed status directly.
	alive := s.connectionGoroutineRunning()
	s.mutex.Unlock()

	if msg.WaitForReady != nil && *msg.WaitForReady && alive {
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

// cachedJWT returns the cached SSH JWT to the identity that obtained it, and a
// miss on a control channel that carries no caller identity.
func (s *Server) cachedJWT(ctx context.Context) (string, bool) {
	caller, ok := ipcauth.CallerIdentity(ctx)
	if !ok {
		// Expected and handled on a control channel with no peer identity: the
		// caller re-authenticates. daemonServerOptions warns about it once at
		// startup, so this stays out of the per-request log.
		log.Debug("not serving the cached SSH JWT: the caller's identity cannot be verified on this control channel")
		return "", false
	}
	return s.jwtCache.get(caller)
}

// RequestJWTAuth initiates JWT authentication flow for SSH
func (s *Server) RequestJWTAuth(
	ctx context.Context,
	msg *proto.RequestJWTAuthRequest,
) (*proto.RequestJWTAuthResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// The generation is read here, with the config and under the same lock, not
	// where the flow is stored below: RequestAuthInfo talks to the IdP in
	// between, and a switch or a logout during that call would otherwise be
	// read as the generation this flow belongs to. SwitchProfile holds
	// s.mutex across its own clear(), so the pair cannot be torn.
	s.mutex.Lock()
	config := s.config
	cacheGeneration := s.jwtCache.currentGeneration()
	s.mutex.Unlock()

	if config == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not configured")
	}

	jwtCacheTTL := s.getJWTCacheTTL()
	if jwtCacheTTL > 0 {
		if cachedToken, found := s.cachedJWT(ctx); found {
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

	// the daemon has no graphical session of its own, only the caller can answer this
	oAuthFlow, err := auth.NewOAuthFlow(ctx, config, msg.GetHasGraphicalSession(), false, hint)
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
	s.oauthAuthFlow.cacheGeneration = cacheGeneration
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
	// Recorded when the flow was created, not read here: the flow survives a
	// profile switch, and everything from RequestJWTAuth to the IdP answering
	// has to count as the same session for the cache.
	generation := s.oauthAuthFlow.cacheGeneration
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
	switch caller, ok := ipcauth.CallerIdentity(ctx); {
	case jwtCacheTTL <= 0:
		log.Debug("JWT caching disabled, not storing token")
	case !ok:
		log.Debug("not caching the SSH JWT: the caller's identity cannot be verified on this control channel")
	default:
		if s.jwtCache.store(token, caller, jwtCacheTTL, generation) {
			log.Debugf("JWT token cached for SSH authentication, TTL: %v", jwtCacheTTL)
		} else {
			log.Debug("not caching the SSH JWT: the session it was obtained under ended while the IdP was polled")
		}
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
	if connectClient.Engine() == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "session can no longer be extended, log in again to reconnect")
	}

	hint := ""
	if msg.Hint != nil {
		hint = *msg.Hint
	}
	if hint == "" {
		hint = profilemanager.GetLoginHint()
	}

	// the daemon has no graphical session of its own, only the caller can answer this
	oAuthFlow, err := auth.NewOAuthFlow(ctx, config, msg.GetHasGraphicalSession(), false, hint)
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
		// Log the full wrapped chain, but return only the innermost gRPC
		// status (code + clean desc) so the UI shows the root cause, not
		// the daemon's wrapping layers.
		log.Errorf("management ExtendAuthSession failed: %v", err)
		if st := innermostStatus(err); st != nil {
			return nil, gstatus.Error(st.Code(), st.Message())
		}
		return nil, gstatus.Errorf(codes.Internal, "%v", err)
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

	resolved, err := s.resolveProfileHandle(req.ProfileName, req.Username)
	if err != nil {
		log.Errorf("failed to resolve profile %q: %v", req.ProfileName, err)
		return nil, err
	}
	cfgPath := resolved.Path
	if cfgPath == "" {
		cfgPath = profilemanager.DefaultConfigPath
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
		RemoteJobsAllowed:             util.ReturnBoolWithDefaultFalse(cfg.RemoteJobsAllowed),
		RosenpassEnabled:              cfg.RosenpassEnabled,
		RosenpassPermissive:           cfg.RosenpassPermissive,
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
		MDMManagedFields:              cfg.Policy().ManagedKeys(),
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

	created, err := s.profileManager.AddProfile(msg.ProfileName, msg.Username)
	if err != nil {
		log.Errorf("failed to create profile: %v", err)
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}

	s.publishProfileListChanged(msg.ProfileName)

	return &proto.AddProfileResponse{Id: created.ID.String()}, nil
}

func (s *Server) RenameProfile(ctx context.Context, msg *proto.RenameProfileRequest) (*proto.RenameProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkProfilesDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
	}

	if msg.Handle == "" || msg.Username == "" || msg.NewProfileName == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "profile name, username and new profile name must be provided")
	}

	resolved, err := s.resolveProfileHandle(msg.Handle, msg.Username)
	if err != nil {
		return nil, err
	}

	err = s.profileManager.RenameProfile(resolved.ID, msg.Username, msg.NewProfileName)
	if err != nil {
		log.Errorf("failed to rename profile: %v", err)
		return nil, fmt.Errorf("failed to rename profile: %w", err)
	}

	s.publishProfileListChanged(msg.NewProfileName)

	return &proto.RenameProfileResponse{OldProfileName: resolved.Name}, nil
}

// RemoveProfile removes a profile from the daemon.
func (s *Server) RemoveProfile(ctx context.Context, msg *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkProfilesDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
	}

	if msg.ProfileName == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "profile name must be provided")
	}

	resolved, err := s.resolveProfileHandle(msg.ProfileName, msg.Username)
	if err != nil {
		return nil, err
	}

	if err := s.logoutFromProfile(ctx, resolved, msg.Username); err != nil {
		// Deregistration is best-effort here: the local profile is removed
		// either way, so an unprivileged caller leaves the peer registered on
		// the management server rather than being blocked from removing it.
		log.Warnf("removing profile %s locally without deregistering it: %v", resolved.ID, err)
	}

	if err := s.profileManager.RemoveProfile(resolved.ID, msg.Username); err != nil {
		log.Errorf("failed to remove profile: %v", err)
		return nil, fmt.Errorf("failed to remove profile: %w", err)
	}

	s.publishProfileListChanged(msg.ProfileName)

	return &proto.RemoveProfileResponse{Id: resolved.ID.String()}, nil
}

// publishProfileListChanged nudges the desktop UI to refresh its profile list
// after a CLI-driven add/remove. The daemon exposes no dedicated
// profile-changed RPC event, and a profile add/remove doesn't move the
// connection status, so the UI's SubscribeStatus path never fires for it (and
// the tray's status-string guard would swallow it anyway). Instead we publish
// a marked INFO/SYSTEM event over SubscribeEvents: the UI's dispatchSystemEvent
// recognises the metadata "kind" marker and translates it into its internal
// profile-changed signal that both the tray menu and the React profile views
// already subscribe to (see proto.MetadataKindProfileListChanged, recognised in
// client/ui/services/daemon_feed.go). userMessage is intentionally empty so this
// stays a silent refresh signal rather than a user-facing notification.
func (s *Server) publishProfileListChanged(profileName string) {
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"Profile list changed",
		"",
		map[string]string{proto.MetadataKindKey: proto.MetadataKindProfileListChanged, proto.MetadataProfileKey: profileName},
	)
}

// publishLogLevelChanged signals the desktop UI that the daemon log level
// changed, so it can attach/detach its rotated gui-client.log. Like
// publishProfileListChanged, this rides the SubscribeEvents stream as a marked
// INFO/SYSTEM event (kind "log-level-changed", level the lowercase logrus
// name); the UI's dispatchSystemEvent recognises the marker and routes it to
// the logging toggle instead of an OS toast (userMessage is empty so it stays
// a silent control signal). The "level" value matches log.Level.String()
// (e.g. "debug", "info") so the UI can parse it directly. See
// proto.MetadataKindLogLevelChanged, recognised in client/ui/services/daemon_feed.go.
func (s *Server) publishLogLevelChanged(level string) {
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"Log level changed",
		"",
		map[string]string{proto.MetadataKindKey: proto.MetadataKindLogLevelChanged, proto.MetadataLevelKey: level},
	)
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
			Id:       profile.ID.String(),
			Name:     profile.Name,
			IsActive: profile.IsActive,
		}
	}

	return response, nil
}

// GetActiveProfile returns the active profile in the daemon. The ProfileName
// field carries the display name for backwards compatibility with UI clients,
// new callers should prefer Id.
func (s *Server) GetActiveProfile(ctx context.Context, msg *proto.GetActiveProfileRequest) (*proto.GetActiveProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	activeProfile, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	// Fallback to legacy name == ID
	displayName := activeProfile.ID.String()
	if activeProfile.ID != profilemanager.DefaultProfileName {
		if profiles, lerr := s.profileManager.ListProfiles(activeProfile.Username); lerr == nil {
			for _, p := range profiles {
				if p.ID == activeProfile.ID {
					displayName = p.Name
					break
				}
			}
		}
	}

	return &proto.GetActiveProfileResponse{
		ProfileName: displayName,
		Username:    activeProfile.Username,
		Id:          activeProfile.ID.String(),
	}, nil
}

// GetFeatures returns the features supported by the daemon.
func (s *Server) GetFeatures(ctx context.Context, msg *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	features := &proto.GetFeaturesResponse{
		DisableProfiles:       s.checkProfilesDisabled(),
		DisableUpdateSettings: s.checkUpdateSettingsDisabled(),
		DisableNetworks:       s.checkNetworksDisabled(),
		DisableAdvancedView:   s.checkDisableAdvancedView(),
	}

	return features, nil
}

// WailsUIReady is a no-op the Wails UI probes at startup; merely answering it
// (rather than returning Unimplemented) tells the UI this daemon is new enough.
func (s *Server) WailsUIReady(context.Context, *proto.WailsUIReadyRequest) (*proto.WailsUIReadyResponse, error) {
	return &proto.WailsUIReadyResponse{}, nil
}

// checkDisableAdvancedView reports the MDM-policy directive for the
// upcoming UI's advanced-view section. Tristate: returns nil when no
// MDM directive is set so the UI applies its own default; returns
// &true / &false when MDM explicitly enforces. No CLI flag backs
// this feature — MDM is the sole source.
func (s *Server) checkDisableAdvancedView() *bool {
	if s.config == nil {
		return nil
	}
	if v, ok := s.config.Policy().GetBool(mdm.KeyDisableAdvancedView); ok {
		return &v
	}
	return nil
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

// MDM authority: when the platform-native MDM source sets a kill switch
// key (regardless of true/false value), that value wins. The CLI flag
// supplied at service install time is the fallback used only when the
// MDM source is silent on the key. This honors the "MDM decides
// everything" semantic agreed for NET-1214 — an admin pushing
// disableX=false via MDM explicitly re-enables the feature even on a
// box installed with --disable-X.
func (s *Server) checkProfilesDisabled() bool {
	if s.config != nil {
		if v, ok := s.config.Policy().GetBool(mdm.KeyDisableProfiles); ok {
			return v
		}
	}
	return s.profilesDisabled
}

// checkNetworksDisabled reports whether the networks/exit-node feature
// is disabled on this daemon instance. Resolved MDM-first: when the
// active policy declares mdm.KeyDisableNetworks the policy value wins
// (regardless of true/false), so an admin can re-enable the feature
// via MDM even on a host that was installed with --disable-networks.
// Falls back to the s.networksDisabled CLI flag when the policy is
// silent on the key. Mirrors checkProfilesDisabled and
// checkUpdateSettingsDisabled.
func (s *Server) checkNetworksDisabled() bool {
	if s.config != nil {
		if v, ok := s.config.Policy().GetBool(mdm.KeyDisableNetworks); ok {
			return v
		}
	}
	return s.networksDisabled
}

func (s *Server) checkUpdateSettingsDisabled() bool {
	if s.config != nil {
		if v, ok := s.config.Policy().GetBool(mdm.KeyDisableUpdateSettings); ok {
			return v
		}
	}
	return s.updateSettingsDisabled
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
// afterLoginPreCheck is a seam for tests to run a concurrent config change
// between Login's first privilege check and the authoritative one.
var afterLoginPreCheck func()

// authorizeAndPrepareLogin makes the authoritative privilege decision for a login
// and, when it passes, carries out every state change that decision authorizes:
// cancelling an login already in progress, switching to the requested profile, and
// persisting the config overrides the request carries.
//
// All of it happens under guardedConfigMu, which SetConfig also holds across its
// own check and write. Login's earlier check refuses the ordinary case before any
// of this is reached; this one exists because that check is not synchronized
// against a concurrent privileged request that enables the SSH server, and a
// caller refused here must not have cancelled or switched anything either.
func (s *Server) authorizeAndPrepareLogin(callerCtx context.Context, msg *proto.LoginRequest, activeProf *profilemanager.ActiveProfileState) (context.Context, *profilemanager.ActiveProfileState, error) {
	if afterLoginPreCheck != nil {
		afterLoginPreCheck()
	}

	s.guardedConfigMu.Lock()
	defer s.guardedConfigMu.Unlock()

	stored, err := s.storedLoginConfig(activeProf, msg)
	if err != nil {
		return nil, nil, err
	}
	if err := requirePrivilegeForConfigChange(callerCtx, stored, privilegedChangeFromLogin(msg)); err != nil {
		return nil, nil, err
	}

	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(callerCtx)
	if md, ok := metadata.FromIncomingContext(callerCtx); ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	s.actCancel = cancel
	s.mutex.Unlock()

	if err := RestoreResidualState(s.rootCtx, s.profileManager.GetStatePath()); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	if msg.ProfileName != nil {
		if _, err := s.switchProfileIfNeeded(*msg.ProfileName, msg.Username, activeProf); err != nil {
			return nil, nil, fmt.Errorf("switch profile: %w", err)
		}
	}

	activeProf, err = s.profileManager.GetActiveProfileState()
	if err != nil {
		return nil, nil, fmt.Errorf("active profile state: %w", err)
	}

	if err := persistLoginOverrides(activeProf, msg.ManagementUrl, msg.OptionalPreSharedKey); err != nil {
		return nil, nil, fmt.Errorf("persist login overrides: %w", err)
	}

	return ctx, activeProf, nil
}

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

// logoutPeerGone reports whether a management Logout failed because the peer
// no longer exists server-side (gRPC NotFound), walking the wrap chain since
// the client wraps the gRPC status with fmt.Errorf.
func logoutPeerGone(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := gstatus.FromError(e); ok && s.Code() == codes.NotFound {
			return true
		}
	}
	return false
}

// innermostStatus walks the wrap chain and returns the deepest gRPC status,
// or nil when none is present. gstatus.FromError does not unwrap, so a status
// wrapped with fmt.Errorf %w would otherwise be missed.
func innermostStatus(err error) *gstatus.Status {
	var found *gstatus.Status
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := gstatus.FromError(e); ok {
			found = s
		}
	}
	return found
}
