package server

import (
	"context"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"sync"

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

	// if configuration exists, we just start connections.
	config, err := internal.ReadConfig(s.managementURL, s.adminURL, s.configPath, nil)
	if err != nil {
		log.Warnf("no config file, skip connection stage: %v", err)
		return nil
	}
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
	defer state.Set(internal.StatusIdle)

	state.Set(internal.StatusConnecting)

	s.mutex.Lock()
	managementURL := s.managementURL
	if msg.ManagementUrl != "" {
		managementURL = msg.ManagementUrl
	}

	adminURL := s.adminURL
	if msg.AdminURL != "" {
		adminURL = msg.AdminURL
	}
	s.mutex.Unlock()

	config, err := internal.GetConfig(managementURL, adminURL, s.configPath, msg.PreSharedKey)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	s.config = config
	s.mutex.Unlock()

	// login operation uses backoff scheme to connect to management API
	// we don't wait for result and return response immediately.
	if err := internal.Login(ctx, s.config, msg.SetupKey, msg.JwtToken); err != nil {
		log.Errorf("failed login: %v", err)
		state.Set(internal.StatusIdle)
		return nil, err
	}

	return &proto.LoginResponse{}, nil
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

	// it should be nill here, but .
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

// Down dengine work in the daemon.
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

	var deviceAuthorizationFlow *proto.DeviceAuthorizationFlow

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

		flowInfo, err := internal.GetDeviceAuthorizationFlowInfo(ctx, s.config)
		if err != nil {
			if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
				log.Warnf("server couldn't find device flow, contact admin: %v", err)
			} else {
				return nil, err
			}
		} else {
			provider, err := toDeviceFlowProvider(flowInfo.Provider)
			if err != nil {
				return nil, fmt.Errorf("retrieved provider name \"%s\" is not in the Provider map", flowInfo.Provider)
			}

			deviceAuthorizationFlow = &proto.DeviceAuthorizationFlow{
				Provider: provider,
				ProviderConfig: &proto.ProviderConfig{
					Audience:     flowInfo.ProviderConfig.Audience,
					ClientID:     flowInfo.ProviderConfig.ClientID,
					ClientSecret: flowInfo.ProviderConfig.ClientSecret,
					Domain:       flowInfo.ProviderConfig.Domain,
				},
			}
		}
	}

	return &proto.GetConfigResponse{
		ManagementUrl:           managementURL,
		AdminURL:                adminURL,
		ConfigFile:              s.configPath,
		LogFile:                 s.logFile,
		PreSharedKey:            preSharedKey,
		DeviceAuthorizationFlow: deviceAuthorizationFlow,
	}, nil
}

func toDeviceFlowProvider(provider string) (proto.DeviceAuthorizationFlowProvider, error) {
	switch strings.ToUpper(provider) {
	case proto.DeviceAuthorizationFlow_HOSTED.String():
		return proto.DeviceAuthorizationFlow_HOSTED, nil
	default:
		var p proto.DeviceAuthorizationFlowProvider
		return p, fmt.Errorf("no provider found for %s, consider updating your client", provider)
	}
}
