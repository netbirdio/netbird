//go:build !android && !ios

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/version"
)

// DebugBundle creates a debug bundle and returns the location.
func (s *Server) DebugBundle(callerCtx context.Context, req *proto.DebugBundleRequest) (resp *proto.DebugBundleResponse, err error) {
	if err := requirePrivilegeForUploadURL(callerCtx, req.GetUploadURL(), req.GetUploadInsecure()); err != nil {
		return nil, err
	}

	// The UI log is opened as whoever asked for this bundle, so a caller only
	// collects a log it owns (privileged callers excepted). ok is false on a
	// socket that carries no identity, which skips the UI log.
	callerID, callerIdentified := ipcauth.CallerIdentity(callerCtx)

	path, managementURL, err := s.generateDebugBundle(req, uiLogOpener(callerID, callerIdentified))
	if err != nil {
		return nil, err
	}

	if req.GetUploadURL() == "" {
		return &proto.DebugBundleResponse{Path: path}, nil
	}

	// The upload runs without s.mutex held: it does network I/O to a possibly
	// slow destination and must not block the other RPCs that take the lock. The
	// bounded context is a backstop against a hung connection.
	uploadCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key, err := debug.UploadDebugBundle(uploadCtx, req.GetUploadURL(), managementURL, path, req.GetUploadInsecure())
	if err != nil {
		log.Errorf("failed to upload debug bundle to %s: %v", req.GetUploadURL(), err)
		return &proto.DebugBundleResponse{Path: path, UploadFailureReason: err.Error()}, nil
	}

	log.Infof("debug bundle uploaded to %s with key %s", req.GetUploadURL(), key)

	return &proto.DebugBundleResponse{Path: path, UploadedKey: key}, nil
}

// generateDebugBundle builds the bundle under s.mutex and returns its path plus
// the management URL captured under the lock, so the caller can run the upload
// without holding the lock.
func (s *Server) generateDebugBundle(req *proto.DebugBundleRequest, uiOpener debug.LogOpener) (path string, managementURL string, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	syncResponse, err := s.getLatestSyncResponse()
	if err != nil {
		log.Warnf("failed to get latest sync response: %v", err)
	}

	var clientMetrics debug.MetricsExporter
	if s.connectClient != nil {
		if engine := s.connectClient.Engine(); engine != nil {
			if cm := engine.GetClientMetrics(); cm != nil {
				clientMetrics = cm
			}
		}
	}

	var cpuProfileData []byte
	if s.cpuProfileBuf != nil && !s.cpuProfiling {
		cpuProfileData = s.cpuProfileBuf.Bytes()
		defer func() {
			s.cpuProfileBuf = nil
		}()
	}

	capturePath := s.bundleCapturePath()
	defer s.cleanupBundleCapture()

	var refreshStatus func()
	if s.connectClient != nil {
		engine := s.connectClient.Engine()
		if engine != nil {
			refreshStatus = func() {
				log.Debug("refreshing system health status for debug bundle")
				// Background ctx: the bundle wants a full, fresh probe regardless
				// of the DebugBundle RPC client's lifetime. The engine's own ctx
				// still aborts it on shutdown.
				engine.RunHealthProbes(context.Background(), true)
			}
		}
	}

	bundleGenerator := debug.NewBundleGenerator(
		debug.GeneratorDependencies{
			InternalConfig: s.config,
			StatusRecorder: s.statusRecorder,
			SyncResponse:   syncResponse,
			LogPath:        s.logFile,
			UILogPath:      s.uiLogPath,
			UILogOpener:    uiOpener,
			CPUProfile:     cpuProfileData,
			CapturePath:    capturePath,
			RefreshStatus:  refreshStatus,
			ClientMetrics:  clientMetrics,
			DaemonVersion:  version.NetbirdVersion(),
			CliVersion:     req.CliVersion,
		},
		debug.BundleConfig{
			Anonymize:         req.GetAnonymize(),
			AnonymizeLevel:    anonymize.ParseLevel(req.GetAnonymizeLevel()),
			IncludeSystemInfo: req.GetSystemInfo(),
			LogFileCount:      req.GetLogFileCount(),
		},
	)

	path, err = bundleGenerator.Generate()
	if err != nil {
		return "", "", fmt.Errorf("generate debug bundle: %w", err)
	}

	if s.config != nil && s.config.ManagementURL != nil {
		managementURL = s.config.ManagementURL.String()
	}

	return path, managementURL, nil
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

	if s.connectClient != nil {
		s.connectClient.SetLogLevel(level)
	}

	log.Infof("Log level set to %s", level.String())

	// Signal the desktop UI so it can attach/detach its gui-client.log. Rides
	// the SubscribeEvents stream as a marked event (see publishLogLevelChanged).
	s.publishLogLevelChanged(level.String())

	return &proto.SetLogLevelResponse{}, nil
}

// RegisterUILog records the desktop UI's absolute log path so DebugBundle can
// collect the GUI log. The daemon runs as root and can't resolve the user's
// config dir, so the UI reports it. Last-writer-wins (one UI per socket).
//
// The path arrives over an IPC any local user can reach and is later opened by
// a root daemon, so it is constrained to the file name the UI writes and to a
// local absolute path. Authorization happens when DebugBundle opens it: the
// bundle refuses a file its requester does not own. A caller the daemon cannot
// identify cannot register a path at all.
func (s *Server) RegisterUILog(callerCtx context.Context, req *proto.RegisterUILogRequest) (*proto.RegisterUILogResponse, error) {
	if _, ok := ipcauth.CallerIdentity(callerCtx); !ok {
		return nil, gstatus.Error(codes.PermissionDenied,
			"registering a UI log path requires a control channel that carries the caller's identity")
	}

	path := filepath.Clean(req.GetPath())
	if !filepath.IsAbs(path) || filepath.Base(path) != uiLogFileName {
		return nil, gstatus.Errorf(codes.InvalidArgument, "UI log path must be an absolute path ending in %s", uiLogFileName)
	}
	// filepath.IsAbs accepts a Windows UNC path (\\host\share\...) and a device
	// path (\\.\, \\?\); opening one would make the root daemon reach a remote
	// or device namespace. Require a plain local path.
	if strings.HasPrefix(path, `\\`) {
		return nil, gstatus.Error(codes.InvalidArgument, "UI log path must be a local path, not a UNC or device path")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.uiLogPath = path
	log.Infof("registered UI log path %s", s.uiLogPath)

	return &proto.RegisterUILogResponse{}, nil
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

// StartCPUProfile starts CPU profiling in the daemon.
func (s *Server) StartCPUProfile(_ context.Context, _ *proto.StartCPUProfileRequest) (*proto.StartCPUProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.cpuProfiling {
		return nil, fmt.Errorf("CPU profiling already in progress")
	}

	s.cpuProfileBuf = &bytes.Buffer{}
	s.cpuProfiling = true
	if err := pprof.StartCPUProfile(s.cpuProfileBuf); err != nil {
		s.cpuProfileBuf = nil
		s.cpuProfiling = false
		return nil, fmt.Errorf("start CPU profile: %w", err)
	}

	log.Info("CPU profiling started")
	return &proto.StartCPUProfileResponse{}, nil
}

// StopCPUProfile stops CPU profiling in the daemon.
func (s *Server) StopCPUProfile(_ context.Context, _ *proto.StopCPUProfileRequest) (*proto.StopCPUProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.cpuProfiling {
		return nil, fmt.Errorf("CPU profiling not in progress")
	}

	pprof.StopCPUProfile()
	s.cpuProfiling = false

	if s.cpuProfileBuf != nil {
		log.Infof("CPU profiling stopped, captured %d bytes", s.cpuProfileBuf.Len())
	}

	return &proto.StopCPUProfileResponse{}, nil
}
