package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestGetAgentNetworkInfo_ClientNotRunning(t *testing.T) {
	s := &Server{}
	_, err := s.GetAgentNetworkInfo(context.Background(), &proto.GetAgentNetworkInfoRequest{})
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "daemon must refuse while the client is down")
}

func TestRelayAgentNetworkInfo(t *testing.T) {
	resp, err := relayAgentNetworkInfo(context.Background(), func(context.Context) (*mgmProto.GetAgentNetworkInfoResponse, error) {
		return &mgmProto.GetAgentNetworkInfoResponse{
			State:    mgmProto.GetAgentNetworkInfoResponse_OK,
			Endpoint: "https://violet.eu.proxy.netbird.io",
			Providers: []*mgmProto.AgentNetworkProvider{{
				Id: "prov-1", Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai",
				AllModelsAllowed: true, Models: []string{"gpt-5.4"},
			}},
		}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, proto.GetAgentNetworkInfoResponse_OK, resp.State)
	assert.Equal(t, "https://violet.eu.proxy.netbird.io", resp.Endpoint)
	require.Len(t, resp.Providers, 1)
	assert.Equal(t, &proto.AgentNetworkProvider{
		Id: "prov-1", Name: "OpenAI", CatalogId: "openai_api", ApiFlavor: "openai",
		AllModelsAllowed: true, Models: []string{"gpt-5.4"},
	}, resp.Providers[0], "provider must relay field for field")
}

func TestRelayAgentNetworkInfo_States(t *testing.T) {
	for mgmState, want := range map[mgmProto.GetAgentNetworkInfoResponse_State]proto.GetAgentNetworkInfoResponse_State{
		mgmProto.GetAgentNetworkInfoResponse_NO_USER:      proto.GetAgentNetworkInfoResponse_NO_USER,
		mgmProto.GetAgentNetworkInfoResponse_NOT_ENABLED:  proto.GetAgentNetworkInfoResponse_NOT_ENABLED,
		mgmProto.GetAgentNetworkInfoResponse_USER_BLOCKED: proto.GetAgentNetworkInfoResponse_USER_BLOCKED,
		mgmProto.GetAgentNetworkInfoResponse_State(99):    proto.GetAgentNetworkInfoResponse_STATE_UNSPECIFIED,
	} {
		resp, err := relayAgentNetworkInfo(context.Background(), func(context.Context) (*mgmProto.GetAgentNetworkInfoResponse, error) {
			return &mgmProto.GetAgentNetworkInfoResponse{State: mgmState}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, want, resp.State, "management state %v", mgmState)
	}
}

func TestRelayAgentNetworkInfo_ManagementUnsupported(t *testing.T) {
	resp, err := relayAgentNetworkInfo(context.Background(), func(context.Context) (*mgmProto.GetAgentNetworkInfoResponse, error) {
		return nil, gstatus.Error(codes.Unimplemented, "unknown method GetAgentNetworkInfo")
	})
	require.NoError(t, err)
	assert.Equal(t, proto.GetAgentNetworkInfoResponse_MANAGEMENT_UNSUPPORTED, resp.State)
}

func TestRelayAgentNetworkInfo_OtherErrorsPassThrough(t *testing.T) {
	_, err := relayAgentNetworkInfo(context.Background(), func(context.Context) (*mgmProto.GetAgentNetworkInfoResponse, error) {
		return nil, gstatus.Error(codes.PermissionDenied, "peer is not registered")
	})
	assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
}
