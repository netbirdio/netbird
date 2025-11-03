package server

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) GetInstallerResult(ctx context.Context, _ *proto.InstallerResultRequest) (*proto.InstallerResultResponse, error) {
	return nil, fmt.Errorf("not implemented")
}
