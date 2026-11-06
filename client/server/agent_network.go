package server

import (
	"context"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// GetAgentNetworkInfo relays what Agent Networks offers this peer.
func (s *Server) GetAgentNetworkInfo(ctx context.Context, _ *proto.GetAgentNetworkInfoRequest) (*proto.GetAgentNetworkInfoResponse, error) {
	s.mutex.Lock()
	if !s.clientRunning {
		s.mutex.Unlock()
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not running, run 'netbird up' first")
	}
	connectClient := s.connectClient
	s.mutex.Unlock()

	if connectClient == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client not initialized")
	}
	engine := connectClient.Engine()
	if engine == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "engine not initialized")
	}

	return relayAgentNetworkInfo(ctx, engine.GetAgentNetworkInfo)
}

type agentNetworkInfoFetcher func(ctx context.Context) (*mgmProto.GetAgentNetworkInfoResponse, error)

// relayAgentNetworkInfo converts the management answer for the daemon API.
// An Unimplemented management means it predates the RPC, which callers
// show as a state rather than an error.
func relayAgentNetworkInfo(ctx context.Context, fetch agentNetworkInfoFetcher) (*proto.GetAgentNetworkInfoResponse, error) {
	info, err := fetch(ctx)
	if gstatus.Code(err) == codes.Unimplemented {
		return &proto.GetAgentNetworkInfoResponse{State: proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED}, nil
	}
	if err != nil {
		return nil, err
	}

	resp := &proto.GetAgentNetworkInfoResponse{
		State:        agentNetworkStateFromMgm(info.GetState()),
		UserEmail:    info.GetUserEmail(),
		Endpoint:     info.GetEndpoint(),
		LoginExpired: info.GetLoginExpired(),
		ComputedAt:   info.GetComputedAt(),
	}
	for _, p := range info.GetProviders() {
		resp.Providers = append(resp.Providers, &proto.AgentNetworkProvider{
			Id:               p.GetId(),
			Name:             p.GetName(),
			CatalogId:        p.GetCatalogId(),
			ApiFlavor:        p.GetApiFlavor(),
			AllModelsAllowed: p.GetAllModelsAllowed(),
			Models:           p.GetModels(),
		})
	}
	return resp, nil
}

func agentNetworkStateFromMgm(state mgmProto.GetAgentNetworkInfoResponse_State) proto.GetAgentNetworkInfoResponse_State {
	switch state {
	case mgmProto.GetAgentNetworkInfoResponse_OK:
		return proto.GetAgentNetworkInfoResponse_OK
	case mgmProto.GetAgentNetworkInfoResponse_NO_USER:
		return proto.GetAgentNetworkInfoResponse_NO_USER
	case mgmProto.GetAgentNetworkInfoResponse_NOT_ENABLED:
		return proto.GetAgentNetworkInfoResponse_NOT_ENABLED
	case mgmProto.GetAgentNetworkInfoResponse_USER_BLOCKED:
		return proto.GetAgentNetworkInfoResponse_USER_BLOCKED
	default:
		return proto.GetAgentNetworkInfoResponse_STATE_UNSPECIFIED
	}
}
