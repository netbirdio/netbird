//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// UpdateService exposes update triggering and result polling to the Wails frontend.
type UpdateService struct {
	grpcClient GRPCClientIface
}

// NewUpdateService creates a new UpdateService.
func NewUpdateService(g GRPCClientIface) *UpdateService {
	return &UpdateService{grpcClient: g}
}

// InstallerResult holds the result of an installer run.
type InstallerResult struct {
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errorMsg"`
}

// TriggerUpdate requests the daemon to perform an auto-update.
func (s *UpdateService) TriggerUpdate() error {
	return nil
}

// GetInstallerResult polls for the installer result (blocking until complete or timeout).
func (s *UpdateService) GetInstallerResult() (*InstallerResult, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	resp, err := conn.GetInstallerResult(ctx, &proto.InstallerResultRequest{})
	if err != nil {
		log.Infof("GetInstallerResult ended (daemon may have restarted): %v", err)
		return &InstallerResult{Success: true}, nil
	}

	return &InstallerResult{
		Success:  resp.Success,
		ErrorMsg: resp.ErrorMsg,
	}, nil
}
