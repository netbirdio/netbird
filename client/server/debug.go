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
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/upload-server/types"
)

const maxBundleUploadSize = 50 * 1024 * 1024

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
	key, err := uploadDebugBundle(context.Background(), req.GetUploadURL(), s.config.ManagementURL.String(), path)
	if err != nil {
		log.Errorf("failed to upload debug bundle to %s: %v", req.GetUploadURL(), err)
		return &proto.DebugBundleResponse{Path: path, UploadFailureReason: err.Error()}, nil
	}

	log.Infof("debug bundle uploaded to %s with key %s", req.GetUploadURL(), key)

	return &proto.DebugBundleResponse{Path: path, UploadedKey: key}, nil
}

func uploadDebugBundle(ctx context.Context, url, managementURL, filePath string) (key string, err error) {
	response, err := getUploadURL(ctx, url, managementURL)
	if err != nil {
		return "", err
	}

	err = upload(ctx, filePath, response)
	if err != nil {
		return "", err
	}
	return response.Key, nil
}

func upload(ctx context.Context, filePath string, response *types.GetURLResponse) error {
	fileData, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}

	defer fileData.Close()

	stat, err := fileData.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if stat.Size() > maxBundleUploadSize {
		return fmt.Errorf("file size exceeds maximum limit of %d bytes", maxBundleUploadSize)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", response.URL, fileData)
	if err != nil {
		return fmt.Errorf("create PUT request: %w", err)
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
		return fmt.Errorf("upload status %d: %s", putResp.StatusCode, string(body))
	}
	return nil
}

func getUploadURL(ctx context.Context, url string, managementURL string) (*types.GetURLResponse, error) {
	id := getURLHash(managementURL)
	getReq, err := http.NewRequestWithContext(ctx, "GET", url+"?id="+id, nil)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}

	getReq.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	resp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("get presigned URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get presigned URL status %d: %s", resp.StatusCode, string(body))
	}

	urlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	var response types.GetURLResponse
	if err := json.Unmarshal(urlBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &response, nil
}

func getURLHash(url string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
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
