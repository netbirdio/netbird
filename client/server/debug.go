//go:build !android && !ios

package server

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// DebugBundle creates a debug bundle and returns the location.
func (s *Server) DebugBundle(_ context.Context, req *proto.DebugBundleRequest) (resp *proto.DebugBundleResponse, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	networkMap, err := s.getLatestNetworkMap()
	if err != nil {
		log.Warnf("failed to get latest network map: %v", err)
	}
	bundleGenerator := debug.NewBundleGenerator(
		debug.GeneratorDependencies{
			InternalConfig: s.config,
			StatusRecorder: s.statusRecorder,
			NetworkMap:     networkMap,
			LogFile:        s.logFile,
		},
		debug.BundleConfig{
			Anonymize:         req.GetAnonymize(),
			ClientStatus:      req.GetStatus(),
			IncludeSystemInfo: req.GetSystemInfo(),
		},
	)

	path, err := bundleGenerator.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate debug bundle: %w", err)
	}

	return &proto.DebugBundleResponse{Path: path}, nil
}

// GetLogLevel gets the current logging level for the server.
func (s *Server) GetLogLevel(_ context.Context, _ *proto.GetLogLevelRequest) (*proto.GetLogLevelResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	level := ParseLogLevel(log.GetLevel().String())
	return &proto.GetLogLevelResponse{Level: level}, nil
}

// SetLogLevel sets the logging level for the server.
func (s *Server) SetLogLevel(_ context.Context, req *proto.SetLogLevelRequest) (*proto.SetLogLevelResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	level, err := log.ParseLevel(req.Level.String())
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	log.SetLevel(level)

	if s.connectClient == nil {
		return nil, fmt.Errorf("connect client not initialized")
	}
	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	fwManager := engine.GetFirewallManager()
	if fwManager == nil {
		return nil, fmt.Errorf("firewall manager not initialized")
	}

	fwManager.SetLogLevel(level)

	log.Infof("Log level set to %s", level.String())

	return &proto.SetLogLevelResponse{}, nil
}

// SetNetworkMapPersistence sets the network map persistence for the server.
func (s *Server) SetNetworkMapPersistence(_ context.Context, req *proto.SetNetworkMapPersistenceRequest) (*proto.SetNetworkMapPersistenceResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	enabled := req.GetEnabled()
	s.persistNetworkMap = enabled
	if s.connectClient != nil {
		s.connectClient.SetNetworkMapPersistence(enabled)
	}

	return &proto.SetNetworkMapPersistenceResponse{}, nil
}

// getLatestNetworkMap returns the latest network map from the engine if network map persistence is enabled
func (s *Server) getLatestNetworkMap() (*mgmProto.NetworkMap, error) {
	if s.connectClient == nil {
		return nil, errors.New("connect client is not initialized")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, errors.New("engine is not initialized")
	}

	networkMap, err := engine.GetLatestNetworkMap()
	if err != nil {
		return nil, fmt.Errorf("get latest network map: %w", err)
	}

	if networkMap == nil {
		return nil, errors.New("network map is not available")
	}

	return networkMap, nil
}
