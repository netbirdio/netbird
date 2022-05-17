package server

import (
	"context"
	"fmt"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

// Server for service control.
type Server struct {
	rootCtx   context.Context
	actCancel context.CancelFunc

	managementURL string
	adminURL      string
	configPath    string
	logFile       string

	oauthClient    internal.OAuthClient
	deviceAuthInfo internal.DeviceAuthInfo

	mutex  sync.Mutex
	config *internal.Config
	proto.UnimplementedDaemonServiceServer
}

// New server instance constructor.
func New(ctx context.Context, managementURL, adminURL, configPath, logFile string) *Server {
	return &Server{
		rootCtx:       ctx,
		managementURL: managementURL,
		adminURL:      adminURL,
		configPath:    configPath,
		logFile:       logFile,
	}
}

func (s *Server) Start() error {
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
	config, err := internal.ReadConfig(s.managementURL, s.adminURL, s.configPath, nil)
	if errorStatus, ok := gstatus.FromError(err); ok && errorStatus.Code() == codes.NotFound {
		config, err = internal.GetConfig(s.managementURL, s.adminURL, s.configPath, "")
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

	s.config = config

	go func() {
		if err := internal.RunClient(ctx, config); err != nil {
			log.Errorf("init connections: %v", err)
		}
	}()

	return nil
}

// Login uses setup key to prepare configuration for the daemon.
func (s *Server) Login(_ context.Context, msg *proto.LoginRequest) (*proto.LoginResponse, error) {
	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
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
	managementURL := s.managementURL
	if msg.ManagementUrl != "" {
		managementURL = msg.ManagementUrl
		s.managementURL = msg.ManagementUrl
	}

	adminURL := s.adminURL
	if msg.AdminURL != "" {
		adminURL = msg.AdminURL
		s.adminURL = msg.AdminURL
	}
	s.mutex.Unlock()

	config, err := internal.GetConfig(managementURL, adminURL, s.configPath, msg.PreSharedKey)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	s.config = config
	s.mutex.Unlock()

	if status, _ := state.Status(); status != internal.StatusNeedsLogin && status != internal.StatusLoginFailed {
		return &proto.LoginResponse{}, nil
	}

	state.Set(internal.StatusConnecting)

	if msg.SetupKey == "" {
		providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config)
		if err != nil {
			state.Set(internal.StatusLoginFailed)
			s, ok := gstatus.FromError(err)
			if ok && s.Code() == codes.NotFound {
				return nil, gstatus.Errorf(codes.NotFound, "no SSO provider returned from management. "+
					"If you are using hosting Netbird see documentation at "+
					"https://github.com/netbirdio/netbird/tree/main/management for details")
			} else if ok && s.Code() == codes.Unimplemented {
				return nil, gstatus.Errorf(codes.Unimplemented, "the management server, %s, does not support SSO providers, "+
					"please update your server or use Setup Keys to login", config.ManagementURL)
			} else {
				log.Errorf("getting device authorization flow info failed with error: %v", err)
				return nil, err
			}
		}

		hostedClient := internal.NewHostedDeviceFlow(
			providerConfig.ProviderConfig.Audience,
			providerConfig.ProviderConfig.ClientID,
			providerConfig.ProviderConfig.Domain,
		)

		deviceAuthInfo, err := hostedClient.RequestDeviceCode(context.TODO())
		if err != nil {
			log.Errorf("getting a request device code failed: %v", err)
			return nil, err
		}

		s.mutex.Lock()
		s.oauthClient = hostedClient
		s.deviceAuthInfo = deviceAuthInfo
		s.mutex.Unlock()

		state.Set(internal.StatusNeedsLogin)

		return &proto.LoginResponse{
			NeedsSSOLogin:           true,
			VerificationURI:         deviceAuthInfo.VerificationURI,
			VerificationURIComplete: deviceAuthInfo.VerificationURIComplete,
			UserCode:                deviceAuthInfo.UserCode,
		}, nil
	}

	if err := internal.Login(ctx, s.config, msg.SetupKey, ""); err != nil {
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			log.Warnf("failed login with known status: %v", err)
			state.Set(internal.StatusNeedsLogin)
		} else {
			log.Errorf("failed login: %v", err)
			state.Set(internal.StatusLoginFailed)
		}
		return nil, err
	}

	return &proto.LoginResponse{}, nil
}

// WaitSSOLogin uses the userCode to validate the TokenInfo and
// waits for the user to continue with the login on a browser
func (s *Server) WaitSSOLogin(_ context.Context, msg *proto.WaitSSOLoginRequest) (*proto.WaitSSOLoginResponse, error) {
	s.mutex.Lock()
	if s.actCancel != nil {
		s.actCancel()
	}
	ctx, cancel := context.WithCancel(s.rootCtx)
	s.actCancel = cancel
	s.mutex.Unlock()

	if s.oauthClient == nil {
		return nil, gstatus.Errorf(codes.Internal, "oauth client is not initialized")
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
	deviceAuthInfo := s.deviceAuthInfo
	s.mutex.Unlock()

	if deviceAuthInfo.UserCode != msg.UserCode {
		state.Set(internal.StatusLoginFailed)
		return nil, gstatus.Errorf(codes.InvalidArgument, "sso user code is invalid")
	}

	waitTimeout := time.Duration(deviceAuthInfo.ExpiresIn)
	waitCTX, cancel := context.WithTimeout(ctx, waitTimeout*time.Second)
	defer cancel()

	tokenInfo, err := s.oauthClient.WaitToken(waitCTX, deviceAuthInfo)
	if err != nil {
		state.Set(internal.StatusLoginFailed)
		log.Errorf("waiting for browser login failed: %v", err)
		return nil, err
	}

	if err := internal.Login(ctx, s.config, "", tokenInfo.AccessToken); err != nil {
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			log.Warnf("failed login: %v", err)
			state.Set(internal.StatusNeedsLogin)
		} else {
			log.Errorf("failed login: %v", err)
			state.Set(internal.StatusLoginFailed)
		}
		return nil, err
	}

	return &proto.WaitSSOLoginResponse{}, nil
}

// Up starts engine work in the daemon.
func (s *Server) Up(_ context.Context, msg *proto.UpRequest) (*proto.UpResponse, error) {
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
	s.actCancel = cancel

	if s.config == nil {
		return nil, fmt.Errorf("config is not defined, please call login command first")
	}

	go func() {
		if err := internal.RunClient(ctx, s.config); err != nil {
			log.Errorf("run client connection: %v", state.Wrap(err))
			return
		}
	}()

	return &proto.UpResponse{}, nil
}

// Down engine work in the daemon.
func (s *Server) Down(ctx context.Context, msg *proto.DownRequest) (*proto.DownResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.actCancel == nil {
		return nil, fmt.Errorf("service is not up")
	}
	s.actCancel()

	return &proto.DownResponse{}, nil
}

// Status starts engine work in the daemon.
func (s *Server) Status(
	ctx context.Context,
	msg *proto.StatusRequest,
) (*proto.StatusResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	status, err := internal.CtxGetState(s.rootCtx).Status()
	if err != nil {
		return nil, err
	}

	return &proto.StatusResponse{Status: string(status)}, nil
}

// GetConfig of the daemon.
func (s *Server) GetConfig(ctx context.Context, msg *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	managementURL := s.managementURL
	adminURL := s.adminURL
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
		ConfigFile:    s.configPath,
		LogFile:       s.logFile,
		PreSharedKey:  preSharedKey,
	}, nil
}
