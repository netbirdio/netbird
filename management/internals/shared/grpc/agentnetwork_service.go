package grpc

import (
	"context"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	antypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// AgentNetworkSetupService is the minimal slice of agentnetwork.Manager
// the peer-facing setup RPC needs. Narrow on purpose so the gRPC server
// never sees the manager's operator-facing surface.
type AgentNetworkSetupService interface {
	GetSetupForPeer(ctx context.Context, accountID, peerID string) (*antypes.EffectiveSetup, error)
}

// GetAgentNetworkSetup handles a peer request for its Agent Network
// connection info. The WireGuard key is the credential (same trust model
// as the Expose RPCs); the response is scoped to what the calling peer's
// own groups authorize and carries display metadata only.
func (s *Server) GetAgentNetworkSetup(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	setupReq := &proto.AgentNetworkSetupRequest{}
	peerKey, err := s.parseRequest(ctx, req, setupReq)
	if err != nil {
		return nil, err
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	setupSvc := s.getAgentNetworkSetupService()
	if setupSvc == nil {
		return nil, status.Errorf(codes.Internal, "agent network manager not available")
	}

	setup, err := setupSvc.GetSetupForPeer(ctx, accountID, peer.ID)
	if err != nil {
		log.WithContext(ctx).Errorf("get agent network setup for peer %s: %v", peer.ID, err)
		return nil, status.Errorf(codes.Internal, "internal error")
	}

	return s.encryptResponse(peerKey, toProtoAgentNetworkSetup(setup))
}

func toProtoAgentNetworkSetup(setup *antypes.EffectiveSetup) *proto.AgentNetworkSetupResponse {
	resp := &proto.AgentNetworkSetupResponse{
		Configured: setup.Configured,
		Endpoint:   setup.Endpoint,
		Providers:  make([]*proto.AgentNetworkProviderInfo, 0, len(setup.Providers)),
	}
	for _, p := range setup.Providers {
		resp.Providers = append(resp.Providers, &proto.AgentNetworkProviderInfo{
			Name:             p.Name,
			CatalogId:        p.CatalogID,
			ApiFlavor:        p.APIFlavor,
			AllModelsAllowed: p.AllModelsAllowed,
			Models:           p.Models,
		})
	}
	return resp
}

func (s *Server) getAgentNetworkSetupService() AgentNetworkSetupService {
	s.agentNetworkSetupMu.RLock()
	defer s.agentNetworkSetupMu.RUnlock()
	return s.agentNetworkSetup
}

// SetAgentNetworkSetupService wires the agent-network setup service on
// the server.
func (s *Server) SetAgentNetworkSetupService(svc AgentNetworkSetupService) {
	s.agentNetworkSetupMu.Lock()
	defer s.agentNetworkSetupMu.Unlock()
	s.agentNetworkSetup = svc
}
