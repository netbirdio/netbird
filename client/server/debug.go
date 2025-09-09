//go:build !android && !ios

package server

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// DebugBundle creates a debug bundle and returns the location.
func (s *Server) DebugBundle(_ context.Context, req *proto.DebugBundleRequest) (resp *proto.DebugBundleResponse, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	syncResponse, err := s.getLatestSyncResponse()
	if err != nil {
		log.Warnf("failed to get latest sync response: %v", err)
	}

	bundleGenerator := debug.NewBundleGenerator(
		debug.GeneratorDependencies{
			InternalConfig: s.config,
			StatusRecorder: s.statusRecorder,
			SyncResponse:   syncResponse,
			LogFile:        s.logFile,
		},
		debug.BundleConfig{
			Anonymize:         req.GetAnonymize(),
			ClientStatus:      req.GetStatus(),
			IncludeSystemInfo: req.GetSystemInfo(),
			LogFileCount:      req.GetLogFileCount(),
		},
	)

	path, err := bundleGenerator.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate debug bundle: %w", err)
	}

	if req.GetUploadURL() == "" {
		return &proto.DebugBundleResponse{Path: path}, nil
	}
	key, err := debug.UploadDebugBundle(context.Background(), req.GetUploadURL(), s.config.ManagementURL.String(), path)
	if err != nil {
		log.Errorf("failed to upload debug bundle to %s: %v", req.GetUploadURL(), err)
		return &proto.DebugBundleResponse{Path: path, UploadFailureReason: err.Error()}, nil
	}

	log.Infof("debug bundle uploaded to %s with key %s", req.GetUploadURL(), key)

	return &proto.DebugBundleResponse{Path: path, UploadedKey: key}, nil
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

// SetSyncResponsePersistence sets the sync response persistence for the server.
func (s *Server) SetSyncResponsePersistence(_ context.Context, req *proto.SetSyncResponsePersistenceRequest) (*proto.SetSyncResponsePersistenceResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	enabled := req.GetEnabled()
	s.persistSyncResponse = enabled
	if s.connectClient != nil {
		s.connectClient.SetSyncResponsePersistence(enabled)
	}

	return &proto.SetSyncResponsePersistenceResponse{}, nil
}

func (s *Server) getLatestSyncResponse() (*mgmProto.SyncResponse, error) {
	cClient := s.connectClient
	if cClient == nil {
		return nil, errors.New("connect client is not initialized")
	}

	return cClient.GetLatestSyncResponse()
}
