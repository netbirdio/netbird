package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) GetInstallerResult(ctx context.Context, _ *proto.InstallerResultRequest) (*proto.InstallerResultResponse, error) {
	inst := installer.New()
	dir := inst.TempDir()

	rh := installer.NewResultHandler(dir)
	result, err := rh.Watch(ctx)
	if err != nil {
		log.Errorf("failed to watch update result: %v", err)
		return &proto.InstallerResultResponse{
			Success:  false,
			ErrorMsg: err.Error(),
		}, nil
	}

	return &proto.InstallerResultResponse{
		Success:  result.Success,
		ErrorMsg: result.Error,
	}, nil
}
