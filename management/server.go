package management

import (
	"context"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"google.golang.org/grpc/status"
)

// Server an instance of a Management server
type Server struct {
	Store *Store
}

// NewServer creates a new Management server
func NewServer() *Server {
	return &Server{
		Store: NewStore(),
	}
}

func (s *Server) RegisterPeer(ctx context.Context, req *proto.RegisterPeerRequest) (*proto.RegisterPeerResponse, error) {

	user := s.Store.AddPeer(req.SetupKey, req.Key)
	if user == nil {
		return &proto.RegisterPeerResponse{}, status.Errorf(404, "provided setup key doesn't exists")
	}

	return &proto.RegisterPeerResponse{}, nil
}

func (s *Server) IsHealthy(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}
