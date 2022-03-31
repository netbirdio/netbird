package server

import (
	"context"
	"fmt"
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
	configPath    string

	mutex  sync.Mutex
	config *internal.Config
	proto.UnimplementedDaemonServiceServer
}

// New server instance constructor.
func New(ctx context.Context, managementURL, configPath string) *Server {
	return &Server{
		rootCtx:       ctx,
		managementURL: managementURL,
		configPath:    configPath,
	}
}

func (s *Server) Start() error {
	state := internal.CtxGetState(s.rootCtx)

	// if current state contains any error, return it
	// in all other cases we can continue execution only if status is idle and up command was
	// not in the progress or already successfully estabilished connection.
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
	config, err := internal.ReadConfig(s.managementURL, s.configPath)
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
	defer s.mutex.Unlock()

	managementURL := s.managementURL
	if msg.ManagementUrl != "" {
		managementURL = msg.ManagementUrl
	}

	config, err := internal.GetConfig(managementURL, s.configPath, msg.PresharedKey)
	if err != nil {
		return nil, err
	}
	s.config = config

	// login operation uses backoff scheme to connect to management API
	// we don't wait for result and return response immediately.
	if err := internal.Login(s.rootCtx, s.config, msg.SetupKey, msg.JwtToken); err != nil {
		log.Errorf("failed login: %v", err)
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
	// not in the progress or already successfully estabilished connection.
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
func (s *Server) Status(ctx context.Context, msg *proto.StatusRequest) (*proto.StatusResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	status, err := internal.CtxGetState(s.rootCtx).Status()
	if err != nil {
		return nil, err
	}

	return &proto.StatusResponse{Status: string(status)}, nil
}
