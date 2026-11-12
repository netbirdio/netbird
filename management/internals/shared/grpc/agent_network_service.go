package grpc

import (
	"context"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// AgentNetworkInfoService answers what Agent Networks offers a peer.
type AgentNetworkInfoService interface {
	GetAgentNetworkInfoForPeer(ctx context.Context, accountID, peerID string) (*types.PeerAgentNetworkInfo, error)
}

// SetAgentNetworkInfoService sets the service behind GetAgentNetworkInfo.
// While unset the RPC answers Unimplemented.
func (s *Server) SetAgentNetworkInfoService(svc AgentNetworkInfoService) {
	s.agentNetworkInfoMu.Lock()
	defer s.agentNetworkInfoMu.Unlock()
	s.agentNetworkInfo = svc
}

func (s *Server) getAgentNetworkInfoService() AgentNetworkInfoService {
	s.agentNetworkInfoMu.RLock()
	defer s.agentNetworkInfoMu.RUnlock()
	return s.agentNetworkInfo
}

// GetAgentNetworkInfo returns what Agent Networks offers the calling peer.
func (s *Server) GetAgentNetworkInfo(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	peerKey, err := s.parseRequest(ctx, req, &proto.GetAgentNetworkInfoRequest{})
	if err != nil {
		return nil, err
	}

	svc := s.getAgentNetworkInfoService()
	if svc == nil {
		return nil, status.Errorf(codes.Unimplemented, "agent network info not available")
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	info, err := svc.GetAgentNetworkInfoForPeer(ctx, accountID, peer.ID)
	if err != nil {
		log.WithContext(ctx).Errorf("get agent network info for peer %s: %v", peer.ID, err)
		return nil, status.Errorf(codes.Internal, "internal error")
	}

	return s.encryptResponse(peerKey, agentNetworkInfoToProto(info))
}

var agentNetworkStateToProto = map[types.PeerAgentNetworkState]proto.GetAgentNetworkInfoResponse_State{
	types.PeerAgentNetworkOK:          proto.GetAgentNetworkInfoResponse_OK,
	types.PeerAgentNetworkNoUser:      proto.GetAgentNetworkInfoResponse_NO_USER,
	types.PeerAgentNetworkNotEnabled:  proto.GetAgentNetworkInfoResponse_NOT_ENABLED,
	types.PeerAgentNetworkUserBlocked: proto.GetAgentNetworkInfoResponse_USER_BLOCKED,
}

func agentNetworkInfoToProto(info *types.PeerAgentNetworkInfo) *proto.GetAgentNetworkInfoResponse {
	resp := &proto.GetAgentNetworkInfoResponse{State: agentNetworkStateToProto[info.State]}
	if info.Config == nil {
		return resp
	}
	resp.Endpoint = info.Config.Endpoint
	for _, p := range info.Config.Providers {
		pp := &proto.AgentNetworkProvider{
			Id:               p.ID,
			Name:             p.Name,
			CatalogId:        p.CatalogID,
			ApiFlavor:        p.APIFlavor,
			AllModelsAllowed: p.AllModelsAllowed,
			Models:           p.Models,
		}
		if a := p.Allowance; a != nil {
			pp.Unlimited = a.Unlimited
			pp.Exhausted = a.Exhausted
			pp.ExhaustedReason = a.ExhaustedReason
			for _, l := range a.Limits {
				pp.Limits = append(pp.Limits, agentNetworkLimitToProto(l))
			}
		}
		resp.Providers = append(resp.Providers, pp)
	}
	return resp
}

var (
	allowanceSourceToProto = map[types.AllowanceSource]proto.AgentNetworkLimit_Source{
		types.AllowanceSourcePolicy:      proto.AgentNetworkLimit_POLICY,
		types.AllowanceSourceAccountRule: proto.AgentNetworkLimit_ACCOUNT_RULE,
	}
	allowanceUnitToProto = map[types.AllowanceUnit]proto.AgentNetworkLimit_Unit{
		types.AllowanceUnitTokens: proto.AgentNetworkLimit_TOKENS,
		types.AllowanceUnitUSD:    proto.AgentNetworkLimit_USD,
	}
	allowanceScopeToProto = map[types.AllowanceScope]proto.AgentNetworkLimit_Scope{
		types.AllowanceScopeUser:  proto.AgentNetworkLimit_USER,
		types.AllowanceScopeGroup: proto.AgentNetworkLimit_GROUP,
	}
)

func agentNetworkLimitToProto(l types.AllowanceLimit) *proto.AgentNetworkLimit {
	return &proto.AgentNetworkLimit{
		Source:        allowanceSourceToProto[l.Source],
		SourceId:      l.SourceID,
		SourceName:    l.SourceName,
		Unit:          allowanceUnitToProto[l.Unit],
		Scope:         allowanceScopeToProto[l.Scope],
		GroupId:       l.GroupID,
		GroupName:     l.GroupName,
		Cap:           l.Cap,
		Used:          l.Used,
		WindowSeconds: l.WindowSeconds,
		WindowStart:   timestamppb.New(l.WindowStart),
		ResetsAt:      timestamppb.New(l.ResetsAt),
	}
}
