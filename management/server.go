package management

import (
	"context"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server an instance of a Management server
type Server struct {
}

// NewServer creates a new Management server
func NewServer() *Server {
	return &Server{}
}

func (*Server) RegisterPeer(ctx context.Context, req *proto.RegisterPeerRequest) (*proto.RegisterPeerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterPeer not implemented")
}

func (*Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsHealthy not implemented")
}
