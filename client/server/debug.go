//go:build !android && !ios

package server

import (
	"bytes"
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

	if req.GetUploadURL() == "" {

		return &proto.DebugBundleResponse{Path: path}, nil
	}
	key, err := uploadDebugBundle(context.Background(), req.GetUploadURL(), s.config.ManagementURL.String(), path)
	if err != nil {
		return &proto.DebugBundleResponse{Path: path}, fmt.Errorf("upload debug bundle: %w", err)
	}

	return &proto.DebugBundleResponse{Path: path, UploadedKey: key}, nil
}

type GetURLResponse struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

func uploadDebugBundle(ctx context.Context, url, managementURL, filePath string) (key string, err error) {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(managementURL)))
	// Step 1: Request a presigned URL from the server
	resp, err := http.Get(url + "?id=" + id)
	if err != nil {
		return "", fmt.Errorf("Failed to get presigned URL: %v", err)
	}
	defer resp.Body.Close()

	urlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var response GetURLResponse
	if err := json.Unmarshal(urlBytes, &response); err != nil {
		return "", fmt.Errorf("Failed to unmarshal response: %v", err)
	}

	// Step 2: Read the file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("Failed to read file: %v", err)
	}

	// Step 3: PUT the file to S3 using the presigned URL
	req, err := http.NewRequest("PUT", response.URL, bytes.NewReader(fileData))
	if err != nil {
		return "", fmt.Errorf("Failed to create PUT request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Upload failed: %v", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		return "", fmt.Errorf("Upload failed with status %d: %s", putResp.StatusCode, string(body))
	}
	return response.Key, nil
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
