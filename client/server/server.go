package server

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
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
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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

	errRestoreResidualState = "failed to restore residual state: %v"
)

// Server for service control.
type Server struct {
	rootCtx   context.Context
	actCancel context.CancelFunc

	logFile string

	oauthAuthFlow oauthAuthFlow

	mutex  sync.Mutex
	config *profilemanager.Config
	proto.UnimplementedDaemonServiceServer

	connectClient *internal.ConnectClient

	statusRecorder *peer.Status
	sessionWatcher *internal.SessionWatcher

	lastProbe         time.Time
	persistNetworkMap bool
	isSessionActive   atomic.Bool

	profileManager profilemanager.ServiceManager
}

type oauthAuthFlow struct {
	expiresAt  time.Time
	flow       auth.OAuthFlow
	info       auth.AuthFlowInfo
	waitCancel context.CancelFunc
}

// New server instance constructor.
func New(ctx context.Context, logFile string) *Server {
	return &Server{
		rootCtx:           ctx,
		logFile:           logFile,
		persistNetworkMap: true,
		statusRecorder:    peer.NewRecorder(""),
		profileManager:    profilemanager.ServiceManager{},
	}
}

func (s *Server) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	state := internal.CtxGetState(s.rootCtx)

	if err := handlePanicLog(); err != nil {
		log.Warnf("failed to redirect stderr: %v", err)
	}

	if err := restoreResidualState(s.rootCtx); err != nil {
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

	// set the default config if not exists
	ok, err := s.profileManager.CopyDefaultProfileIfNotExists()
	if err != nil {
		if err := s.profileManager.CreateDefaultProfile(); err != nil {
			log.Errorf("failed to create default profile: %v", err)
			return fmt.Errorf("failed to create default profile: %w", err)
		}

		if err := s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			Name:     "default",
			Username: "",
		}); err != nil {
			log.Errorf("failed to set active profile state: %v", err)
			return fmt.Errorf("failed to set active profile state: %w", err)
		}
	}
	if ok {
		state.Set(internal.StatusNeedsLogin)
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return fmt.Errorf("failed to get active profile state: %w", err)
	}

	cfgPath, err := activeProf.FilePath()
	if err != nil {
		log.Errorf("failed to get active profile file path: %v", err)
		return fmt.Errorf("failed to get active profile file path: %w", err)
	}

	config, err := profilemanager.GetConfig(cfgPath)
	if err != nil {
		log.Errorf("failed to get active profile config: %v", err)

		if err := s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{
			Name:     "default",
			Username: "",
		}); err != nil {
			log.Errorf("failed to set active profile state: %v", err)
			return fmt.Errorf("failed to set active profile state: %w", err)
		}

		config, err = profilemanager.GetConfig(s.profileManager.DefaultProfilePath())
		if err != nil {
			log.Errorf("failed to get default profile config: %v", err)
			return fmt.Errorf("failed to get default profile config: %w", err)
		}
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
		return nil
	}

	go s.connectWithRetryRuns(ctx, config, s.statusRecorder, nil)

	return nil
}

// connectWithRetryRuns runs the client connection with a backoff strategy where we retry the operation as additional
// mechanism to keep the client connected even when the connection is lost.
// we cancel retry if the client receive a stop or down command, or if disable auto connect is configured.
func (s *Server) connectWithRetryRuns(ctx context.Context, config *profilemanager.Config, statusRecorder *peer.Status,
	runningChan chan struct{},
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
		s.connectClient.SetNetworkMapPersistence(s.persistNetworkMap)

		err := s.connectClient.Run(runningChan)
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
func (s *Server) SetConfig(callerCtx context.Context, msg *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	config, err := profilemanager.GetConfig(s.profileManager.DefaultProfilePath())
	if err != nil {
		log.Errorf("failed to get default profile config: %v", err)
		return nil, fmt.Errorf("failed to get default profile config: %w", err)
	}

	//profilemanager.CreateInMemoryConfig()

	/*
		// managementUrl to authenticate.
		ManagementUrl string `protobuf:"bytes,1,opt,name=managementUrl,proto3" json:"managementUrl,omitempty"`
		// adminUrl to manage keys.
		AdminURL              string  `protobuf:"bytes,2,opt,name=adminURL,proto3" json:"adminURL,omitempty"`
		RosenpassEnabled      *bool   `protobuf:"varint,3,opt,name=rosenpassEnabled,proto3,oneof" json:"rosenpassEnabled,omitempty"`
		InterfaceName         *string `protobuf:"bytes,4,opt,name=interfaceName,proto3,oneof" json:"interfaceName,omitempty"`
		WireguardPort         *int64  `protobuf:"varint,5,opt,name=wireguardPort,proto3,oneof" json:"wireguardPort,omitempty"`
		OptionalPreSharedKey  *string `protobuf:"bytes,6,opt,name=optionalPreSharedKey,proto3,oneof" json:"optionalPreSharedKey,omitempty"`
		DisableAutoConnect    *bool   `protobuf:"varint,7,opt,name=disableAutoConnect,proto3,oneof" json:"disableAutoConnect,omitempty"`
		ServerSSHAllowed      *bool   `protobuf:"varint,8,opt,name=serverSSHAllowed,proto3,oneof" json:"serverSSHAllowed,omitempty"`
		RosenpassPermissive   *bool   `protobuf:"varint,9,opt,name=rosenpassPermissive,proto3,oneof" json:"rosenpassPermissive,omitempty"`
		NetworkMonitor        *bool   `protobuf:"varint,10,opt,name=networkMonitor,proto3,oneof" json:"networkMonitor,omitempty"`
		DisableClientRoutes   *bool   `protobuf:"varint,11,opt,name=disable_client_routes,json=disableClientRoutes,proto3,oneof" json:"disable_client_routes,omitempty"`
		DisableServerRoutes   *bool   `protobuf:"varint,12,opt,name=disable_server_routes,json=disableServerRoutes,proto3,oneof" json:"disable_server_routes,omitempty"`
		DisableDns            *bool   `protobuf:"varint,13,opt,name=disable_dns,json=disableDns,proto3,oneof" json:"disable_dns,omitempty"`
		DisableFirewall       *bool   `protobuf:"varint,14,opt,name=disable_firewall,json=disableFirewall,proto3,oneof" json:"disable_firewall,omitempty"`
		BlockLanAccess        *bool   `protobuf:"varint,15,opt,name=block_lan_access,json=blockLanAccess,proto3,oneof" json:"block_lan_access,omitempty"`
		DisableNotifications  *bool   `protobuf:"varint,16,opt,name=disable_notifications,json=disableNotifications,proto3,oneof" json:"disable_notifications,omitempty"`
		LazyConnectionEnabled *bool   `protobuf:"varint,17,opt,name=lazyConnectionEnabled,proto3,oneof" json:"lazyConnectionEnabled,omitempty"`
		BlockInbound          *bool   `protobuf:"varint,18,opt,name=block_inbound,json=blockInbound,proto3,oneof" json:"block_inbound,omitempty"`
	*/

	if msg.ManagementUrl != "" {
		managementURL, err := url.Parse(msg.ManagementUrl)
		if err != nil {
			log.Errorf("failed to parse management URL: %v", err)
			return nil, fmt.Errorf("failed to parse management URL: %w", err)
		}
		config.ManagementURL = managementURL
	}

	if msg.AdminURL != "" {
		adminURL, err := url.Parse(msg.AdminURL)
		if err != nil {
			log.Errorf("failed to parse admin URL: %v", err)
			return nil, fmt.Errorf("failed to parse admin URL: %w", err)
		}
		config.AdminURL = adminURL
	}

	if msg.InterfaceName != nil {
		config.WgIface = *msg.InterfaceName
	}

	if msg.WireguardPort != nil {
		config.WgPort = int(*msg.WireguardPort)
	}

	if msg.OptionalPreSharedKey != nil {
		if *msg.OptionalPreSharedKey != "" {
			config.PreSharedKey = *msg.OptionalPreSharedKey
		} else {
			config.PreSharedKey = ""
		}
	}
	if msg.RosenpassEnabled != nil {
		config.RosenpassEnabled = *msg.RosenpassEnabled
	}

	if msg.RosenpassPermissive != nil {
		config.RosenpassPermissive = *msg.RosenpassPermissive
	}

	if msg.DisableAutoConnect != nil {
		config.DisableAutoConnect = *msg.DisableAutoConnect
	}

	if msg.ServerSSHAllowed != nil {
		config.ServerSSHAllowed = msg.ServerSSHAllowed
	}

	if msg.NetworkMonitor != nil {
		config.NetworkMonitor = msg.NetworkMonitor
	}

	if msg.DisableClientRoutes != nil {
		config.DisableClientRoutes = *msg.DisableClientRoutes
	}

	if msg.DisableServerRoutes != nil {
		config.DisableServerRoutes = *msg.DisableServerRoutes
	}

	if msg.DisableDns != nil {
		config.DisableDNS = *msg.DisableDns
	}

	if msg.DisableFirewall != nil {
		config.DisableFirewall = *msg.DisableFirewall
	}

	if msg.BlockLanAccess != nil {
		config.BlockLANAccess = *msg.BlockLanAccess
	}

	if msg.DisableNotifications != nil {
		config.DisableNotifications = msg.DisableNotifications
	}

	if msg.LazyConnectionEnabled != nil {
		config.LazyConnectionEnabled = *msg.LazyConnectionEnabled
	}

	if msg.BlockInbound != nil {
		config.BlockInbound = *msg.BlockInbound
	}

	// if err := profilemanager.UpdateConfig(); err != nil {
	// 	log.Errorf("failed to update default profile config: %v", err)
	// 	return nil, fmt.Errorf("failed to update default profile config: %w", err)
	// }

	return &proto.SetConfigResponse{}, nil
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

	if err := restoreResidualState(ctx); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	state := internal.CtxGetState(ctx)
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
			log.Infof("switching to profile %s for user %s", *msg.ProfileName, username)
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

	cfgPath, err := activeProf.FilePath()
	if err != nil {
		log.Errorf("failed to get active profile file path: %v", err)
		return nil, fmt.Errorf("failed to get active profile file path: %w", err)
	}

	config, err := profilemanager.GetConfig(cfgPath)
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
		oAuthFlow, err := auth.NewOAuthFlow(ctx, config, msg.IsUnixDesktopClient)
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
	defer s.mutex.Unlock()

	if err := restoreResidualState(callerCtx); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

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

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	if msg != nil && msg.ProfileName != nil {
		if *msg.ProfileName != "default" && (msg.Username == nil || *msg.Username == "") {
			log.Errorf("profile name is set to %s, but username is not provided", *msg.ProfileName)
			return nil, fmt.Errorf("profile name is set to %s, but username is not provided", *msg.ProfileName)
		}

		var username string
		if *msg.ProfileName != "default" {
			username = *msg.Username
		}

		if *msg.ProfileName != activeProf.Name && username != activeProf.Username {
			log.Infof("switching to profile %s for user %s", *msg.ProfileName, username)
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

	cfgPath, err := activeProf.FilePath()
	if err != nil {
		log.Errorf("failed to get active profile file path: %v", err)
		return nil, fmt.Errorf("failed to get active profile file path: %w", err)
	}

	config, err := profilemanager.GetConfig(cfgPath)
	if err != nil {
		log.Errorf("failed to get active profile config: %v", err)
		return nil, fmt.Errorf("failed to get active profile config: %w", err)
	}
	s.config = config

	s.statusRecorder.UpdateManagementAddress(s.config.ManagementURL.String())
	s.statusRecorder.UpdateRosenpass(s.config.RosenpassEnabled, s.config.RosenpassPermissive)

	timeoutCtx, cancel := context.WithTimeout(callerCtx, 50*time.Second)
	defer cancel()

	runningChan := make(chan struct{}, 1) // buffered channel to do not lose the signal
	go s.connectWithRetryRuns(ctx, s.config, s.statusRecorder, runningChan)
	for {
		select {
		case <-runningChan:
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
}

// SwitchProfile switches the active profile in the daemon.
func (s *Server) SwitchProfile(callerCtx context.Context, msg *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := restoreResidualState(callerCtx); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Errorf("failed to get active profile state: %v", err)
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}

	if msg != nil && msg.ProfileName != nil {
		if *msg.ProfileName != "default" && (msg.Username == nil || *msg.Username == "") {
			log.Errorf("profile name is set to %s, but username is not provided", *msg.ProfileName)
			return nil, fmt.Errorf("profile name is set to %s, but username is not provided", *msg.ProfileName)
		}

		var username string
		if *msg.ProfileName != "default" {
			username = *msg.Username
		}

		if *msg.ProfileName != activeProf.Name && username != activeProf.Username {
			log.Infof("switching to profile %s for user %s", *msg.ProfileName, username)
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

	cfgPath, err := activeProf.FilePath()
	if err != nil {
		log.Errorf("failed to get active profile file path: %v", err)
		return nil, fmt.Errorf("failed to get active profile file path: %w", err)
	}

	config, err := profilemanager.GetConfig(cfgPath)
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
	defer s.mutex.Unlock()

	s.oauthAuthFlow = oauthAuthFlow{}

	if s.actCancel == nil {
		return nil, fmt.Errorf("service is not up")
	}
	s.actCancel()

	err := s.connectClient.Stop()
	if err != nil {
		log.Errorf("failed to shut down properly: %v", err)
		return nil, err
	}
	s.isSessionActive.Store(false)

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusIdle)

	log.Infof("service is down")

	return &proto.DownResponse{}, nil
}

// Status returns the daemon status
func (s *Server) Status(
	ctx context.Context,
	msg *proto.StatusRequest,
) (*proto.StatusResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

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
		if msg.ShouldRunProbes {
			s.runProbes()
		}

		fullStatus := s.statusRecorder.GetFullStatus()
		pbFullStatus := toProtoFullStatus(fullStatus)
		pbFullStatus.Events = s.statusRecorder.GetEventHistory()
		statusResponse.FullStatus = pbFullStatus
	}

	return &statusResponse, nil
}

func (s *Server) runProbes() {
	if s.connectClient == nil {
		return
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return
	}

	if time.Since(s.lastProbe) > probeThreshold {
		if engine.RunHealthProbes() {
			s.lastProbe = time.Now()
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
	preSharedKey := ""

	preSharedKey = cfg.PreSharedKey
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

	return &proto.GetConfigResponse{
		ManagementUrl:         managementURL.String(),
		PreSharedKey:          preSharedKey,
		AdminURL:              adminURL.String(),
		InterfaceName:         cfg.WgIface,
		WireguardPort:         int64(cfg.WgPort),
		DisableAutoConnect:    cfg.DisableAutoConnect,
		ServerSSHAllowed:      *cfg.ServerSSHAllowed,
		RosenpassEnabled:      cfg.RosenpassEnabled,
		RosenpassPermissive:   cfg.RosenpassPermissive,
		LazyConnectionEnabled: cfg.LazyConnectionEnabled,
		BlockInbound:          cfg.BlockInbound,
		DisableNotifications:  disableNotifications,
		NetworkMonitor:        networkMonitor,
		DisableDns:            disableDNS,
		DisableClientRoutes:   disableClientRoutes,
		DisableServerRoutes:   disableServerRoutes,
		BlockLanAccess:        blockLANAccess,
	}, nil
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
	pbFullStatus.LocalPeerState.Networks = maps.Keys(fullStatus.LocalPeerState.Routes)
	pbFullStatus.NumberOfForwardingRules = int32(fullStatus.NumOfForwardingRules)
	pbFullStatus.LazyConnectionEnabled = fullStatus.LazyConnectionEnabled

	for _, peerState := range fullStatus.Peers {
		pbPeerState := &proto.PeerState{
			IP:                         peerState.IP,
			PubKey:                     peerState.PubKey,
			ConnStatus:                 peerState.ConnStatus.String(),
			ConnStatusUpdate:           timestamppb.New(peerState.ConnStatusUpdate),
			Relayed:                    peerState.Relayed,
			LocalIceCandidateType:      peerState.LocalIceCandidateType,
			RemoteIceCandidateType:     peerState.RemoteIceCandidateType,
			LocalIceCandidateEndpoint:  peerState.LocalIceCandidateEndpoint,
			RemoteIceCandidateEndpoint: peerState.RemoteIceCandidateEndpoint,
			RelayAddress:               peerState.RelayServerAddress,
			Fqdn:                       peerState.FQDN,
			LastWireguardHandshake:     timestamppb.New(peerState.LastWireguardHandshake),
			BytesRx:                    peerState.BytesRx,
			BytesTx:                    peerState.BytesTx,
			RosenpassEnabled:           peerState.RosenpassEnabled,
			Networks:                   maps.Keys(peerState.GetRoutes()),
			Latency:                    durationpb.New(peerState.Latency),
		}
		pbFullStatus.Peers = append(pbFullStatus.Peers, pbPeerState)
	}

	for _, relayState := range fullStatus.Relays {
		pbRelayState := &proto.RelayState{
			URI:       relayState.URI,
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

// AddProfile adds a new profile to the daemon.
func (s *Server) AddProfile(ctx context.Context, msg *proto.AddProfileRequest) (*proto.AddProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := restoreResidualState(ctx); err != nil {
		log.Warnf(errRestoreResidualState, err)
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

	if err := restoreResidualState(ctx); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

	if msg.ProfileName == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "profile name must be provided")
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

	if err := restoreResidualState(ctx); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}

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
