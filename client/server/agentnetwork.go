package server

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// GetAgentNetworkSetup relays the peer's Agent Network setup request to the
// management server over the engine's existing connection. Running through
// the daemon keeps the WireGuard key inside the daemon — unprivileged CLI
// callers get a caller-scoped answer without reading the profile config.
func (s *Server) GetAgentNetworkSetup(ctx context.Context, _ *proto.GetAgentNetworkSetupRequest) (*proto.GetAgentNetworkSetupResponse, error) {
	s.mutex.Lock()
	clientRunning := s.clientRunning
	connectClient := s.connectClient
	s.mutex.Unlock()

	if !clientRunning || connectClient == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not running, run 'netbird up' first")
	}
	engine := connectClient.Engine()
	if engine == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "engine not initialized")
	}

	setupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	setup, err := engine.GetAgentNetworkSetup(setupCtx)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "get agent network setup: %v", err)
	}

	return toDaemonAgentNetworkSetup(setup), nil
}

func toDaemonAgentNetworkSetup(setup *mgmProto.AgentNetworkSetupResponse) *proto.GetAgentNetworkSetupResponse {
	resp := &proto.GetAgentNetworkSetupResponse{
		Configured: setup.Configured,
		Endpoint:   setup.Endpoint,
		Providers:  make([]*proto.AgentNetworkProvider, 0, len(setup.Providers)),
	}
	for _, p := range setup.Providers {
		resp.Providers = append(resp.Providers, &proto.AgentNetworkProvider{
			Name:             p.Name,
			CatalogId:        p.CatalogId,
			ApiFlavor:        p.ApiFlavor,
			AllModelsAllowed: p.AllModelsAllowed,
			Models:           p.Models,
		})
	}
	return resp
}
