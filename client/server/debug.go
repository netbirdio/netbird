//go:build !android && !ios

package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/upload-server/types"
)

const maxBundleUploadSize = 50 * 1024 * 1024

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

	if req.GetUploadURL() == "" {

		return &proto.DebugBundleResponse{Path: path}, nil
	}
	key, err := uploadDebugBundle(context.Background(), req.GetUploadURL(), s.config.ManagementURL.String(), path)
	if err != nil {
		return &proto.DebugBundleResponse{Path: path, UploadFailureReason: err.Error()}, nil
	}

	return &proto.DebugBundleResponse{Path: path, UploadedKey: key}, nil
}

func uploadDebugBundle(ctx context.Context, url, managementURL, filePath string) (key string, err error) {
	response, err := getUploadURL(ctx, url, managementURL, err)
	if err != nil {
		return "", err
	}

	err = upload(ctx, err, filePath, response)
	if err != nil {
		return "", err
	}
	return response.Key, nil
}

func upload(ctx context.Context, err error, filePath string, response *types.GetURLResponse) error {
	fileData, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	defer fileData.Close()

	stat, err := fileData.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	if stat.Size() > maxBundleUploadSize {
		return fmt.Errorf("file size exceeds maximum limit of %d bytes", maxBundleUploadSize)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", response.URL, fileData)
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %v", err)
	}

	req.ContentLength = stat.Size()
	req.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %v", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("upload failed with status %d: %s", putResp.StatusCode, string(body))
	}
	return nil
}

func getUploadURL(ctx context.Context, url string, managementURL string, err error) (*types.GetURLResponse, error) {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(managementURL)))
	getReq, err := http.NewRequestWithContext(ctx, "GET", url+"?id="+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %v", err)
	}

	getReq.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	resp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get presigned URL: %v", err)
	}
	defer resp.Body.Close()

	urlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	var response types.GetURLResponse
	if err := json.Unmarshal(urlBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return &response, nil
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
	cClient := s.connectClient
	if cClient == nil {
		return nil, errors.New("connect client is not initialized")
	}

	return cClient.GetLatestNetworkMap()
}
