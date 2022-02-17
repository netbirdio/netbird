package server

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
)

// Server for service control.
type Server struct {
	managementURL string
	configPath    string
	stopCh        chan int
	cleanupCh     chan<- struct{}

	config *internal.Config
	proto.UnimplementedDaemonServiceServer
}

// New server instance constructor.
func New(managementURL, configPath string, stopCh chan int, cleanupCh chan<- struct{}) *Server {
	return &Server{
		managementURL: managementURL,
		configPath:    configPath,
		stopCh:        stopCh,
		cleanupCh:     cleanupCh,
	}
}

// Login uses setup key to prepare configuration for the daemon.
func (s *Server) Login(ctx context.Context, msg *proto.LoginRequest) (*proto.LoginResponse, error) {
	config, err := internal.GetConfig(s.managementURL, s.configPath, msg.PresharedKey)
	if err != nil {
		return nil, err
	}
	s.config = config

	// login operation uses backoff scheme to connect to management API
	// we don't wait for result and return response immediately.
	go func() {
		if err := internal.Login(s.config, msg.SetupKey); err != nil {
			log.Errorf("failed login: %v", err)
		}
	}()

	return &proto.LoginResponse{}, nil
}

// Up starts engine work in the daemon.
func (s *Server) Up(ctx context.Context, msg *proto.UpRequest) (*proto.UpResponse, error) {
	if s.config == nil {
		return nil, fmt.Errorf("config is not defined, please call login command first")
	}

	// connect operation uses backoff scheme to grab configuration from management API
	// we don't wait for result and return response immediately.
	go func() {
		if err := internal.RunClient(s.config, s.stopCh, s.cleanupCh); err != nil {
			log.Errorf("run client connection: %v", err)
		}
	}()

	return &proto.UpResponse{}, nil
}

// Down dengine work in the daemon.
func (s *Server) Down(ctx context.Context, msg *proto.DownRequest) (*proto.DownResponse, error) {
	// put to queue and don't wait it will be accepted
	go func() {
		s.stopCh <- 1
	}()

	return &proto.DownResponse{}, nil
}
