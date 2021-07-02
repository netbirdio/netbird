package management

import (
	"context"
	"github.com/wiretrustee/wiretrustee/management/proto"
)

// Server an instance of a Management server
type Server struct {
}

// NewServer creates a new Management server
func NewServer() *Server {
	return &Server{}
}

func (*Server) RegisterPeer(ctx context.Context, req *proto.RegisterPeerRequest) (*proto.RegisterPeerResponse, error) {
	return &proto.RegisterPeerResponse{}, nil
}

func (*Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}
