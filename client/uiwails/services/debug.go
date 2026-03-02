//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// DebugService exposes debug bundle creation and log-level control to the Wails frontend.
type DebugService struct {
	grpcClient GRPCClientIface
}

// NewDebugService creates a new DebugService.
func NewDebugService(g GRPCClientIface) *DebugService {
	return &DebugService{grpcClient: g}
}

// DebugBundleParams holds the parameters for creating a debug bundle.
type DebugBundleParams struct {
	Anonymize         bool   `json:"anonymize"`
	SystemInfo        bool   `json:"systemInfo"`
	Upload            bool   `json:"upload"`
	UploadURL         string `json:"uploadUrl"`
	RunDurationMins   int    `json:"runDurationMins"`
	EnablePersistence bool   `json:"enablePersistence"`
}

// DebugBundleResult holds the result of creating a debug bundle.
type DebugBundleResult struct {
	LocalPath           string `json:"localPath"`
	UploadedKey         string `json:"uploadedKey"`
	UploadFailureReason string `json:"uploadFailureReason"`
}

// CreateDebugBundle creates a debug bundle via the daemon.
func (s *DebugService) CreateDebugBundle(params DebugBundleParams) (*DebugBundleResult, error) {
	conn, err := s.grpcClient.GetClient(time.Second)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if params.RunDurationMins > 0 {
		if err := s.configureForDebug(ctx, conn, params); err != nil {
			return nil, err
		}
	}

	req := &proto.DebugBundleRequest{
		Anonymize:  params.Anonymize,
		SystemInfo: params.SystemInfo,
	}
	if params.Upload && params.UploadURL != "" {
		req.UploadURL = params.UploadURL
	}

	resp, err := conn.DebugBundle(ctx, req)
	if err != nil {
		log.Errorf("DebugBundle rpc failed: %v", err)
		return nil, fmt.Errorf("create debug bundle: %w", err)
	}

	return &DebugBundleResult{
		LocalPath:           resp.GetPath(),
		UploadedKey:         resp.GetUploadedKey(),
		UploadFailureReason: resp.GetUploadFailureReason(),
	}, nil
}

func (s *DebugService) configureForDebug(ctx context.Context, conn proto.DaemonServiceClient, params DebugBundleParams) error {
	statusResp, err := conn.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	wasConnected := statusResp.Status == "Connected" || statusResp.Status == "Connecting"

	logLevelResp, err := conn.GetLogLevel(ctx, &proto.GetLogLevelRequest{})
	if err != nil {
		return fmt.Errorf("get log level: %w", err)
	}
	originalLogLevel := logLevelResp.GetLevel()

	// Set trace log level
	if _, err := conn.SetLogLevel(ctx, &proto.SetLogLevelRequest{Level: proto.LogLevel_TRACE}); err != nil {
		return fmt.Errorf("set log level: %w", err)
	}

	// Bring service down then up to capture full connection logs
	if _, err := conn.Down(ctx, &proto.DownRequest{}); err != nil {
		log.Warnf("bring down for debug: %v", err)
	}
	time.Sleep(time.Second)

	if params.EnablePersistence {
		if _, err := conn.SetSyncResponsePersistence(ctx, &proto.SetSyncResponsePersistenceRequest{Enabled: true}); err != nil {
			log.Warnf("enable sync persistence: %v", err)
		}
	}

	if _, err := conn.Up(ctx, &proto.UpRequest{}); err != nil {
		return fmt.Errorf("bring service up: %w", err)
	}
	time.Sleep(3 * time.Second)

	if _, err := conn.StartCPUProfile(ctx, &proto.StartCPUProfileRequest{}); err != nil {
		log.Warnf("start CPU profiling: %v", err)
	}

	// Wait for the collection duration
	collectionDur := time.Duration(params.RunDurationMins) * time.Minute
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(collectionDur):
	}

	if _, err := conn.StopCPUProfile(ctx, &proto.StopCPUProfileRequest{}); err != nil {
		log.Warnf("stop CPU profiling: %v", err)
	}

	// Restore original state
	if !wasConnected {
		if _, err := conn.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Warnf("restore down state: %v", err)
		}
	}

	if originalLogLevel < proto.LogLevel_TRACE {
		if _, err := conn.SetLogLevel(ctx, &proto.SetLogLevelRequest{Level: originalLogLevel}); err != nil {
			log.Warnf("restore log level: %v", err)
		}
	}

	return nil
}

// GetLogLevel returns the current daemon log level.
func (s *DebugService) GetLogLevel() (string, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return "", fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.GetLogLevel(ctx, &proto.GetLogLevelRequest{})
	if err != nil {
		return "", fmt.Errorf("get log level rpc: %w", err)
	}

	return resp.GetLevel().String(), nil
}

// SetLogLevel sets the daemon log level.
func (s *DebugService) SetLogLevel(level string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var protoLevel proto.LogLevel
	switch level {
	case "TRACE":
		protoLevel = proto.LogLevel_TRACE
	case "DEBUG":
		protoLevel = proto.LogLevel_DEBUG
	case "INFO":
		protoLevel = proto.LogLevel_INFO
	case "WARN", "WARNING":
		protoLevel = proto.LogLevel_WARN
	case "ERROR":
		protoLevel = proto.LogLevel_ERROR
	default:
		protoLevel = proto.LogLevel_INFO
	}

	if _, err := conn.SetLogLevel(ctx, &proto.SetLogLevelRequest{Level: protoLevel}); err != nil {
		return fmt.Errorf("set log level rpc: %w", err)
	}

	return nil
}
