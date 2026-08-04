package client

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

// agentNetworkSetupServer is a minimal ManagementService that answers
// GetServerKey and GetAgentNetworkSetup with the real NaCl-box envelope,
// so the test pins the full wire path: gRPC method routing, request
// encryption, and response decryption.
type agentNetworkSetupServer struct {
	mgmtProto.UnimplementedManagementServiceServer
	key wgtypes.Key
}

func (s *agentNetworkSetupServer) GetServerKey(_ context.Context, _ *mgmtProto.Empty) (*mgmtProto.ServerKeyResponse, error) {
	return &mgmtProto.ServerKeyResponse{Key: s.key.PublicKey().String()}, nil
}

func (s *agentNetworkSetupServer) GetAgentNetworkSetup(_ context.Context, msg *mgmtProto.EncryptedMessage) (*mgmtProto.EncryptedMessage, error) {
	peerKey, err := wgtypes.ParseKey(msg.WgPubKey)
	if err != nil {
		return nil, err
	}
	req := &mgmtProto.AgentNetworkSetupRequest{}
	if err := encryption.DecryptMessage(peerKey, s.key, msg.Body, req); err != nil {
		return nil, err
	}
	resp := &mgmtProto.AgentNetworkSetupResponse{
		Configured: true,
		Endpoint:   "https://violet.eu.proxy.example.com",
		Providers: []*mgmtProto.AgentNetworkProviderInfo{
			{
				Name:      "Anthropic prod",
				CatalogId: "anthropic_api",
				ApiFlavor: "anthropic",
				Models:    []string{"claude-sonnet-4-5"},
			},
		},
	}
	body, err := encryption.EncryptMessage(peerKey, s.key, resp)
	if err != nil {
		return nil, err
	}
	return &mgmtProto.EncryptedMessage{WgPubKey: s.key.PublicKey().String(), Body: body}, nil
}

// TestGetAgentNetworkSetup_RoundTrip proves the RPC is routable on any
// server built from this tree and that the encrypt→invoke→decrypt path
// the CLI uses round-trips. A server answering this call with
// codes.Unimplemented is by definition running a binary compiled without
// the regenerated management proto.
func TestGetAgentNetworkSetup_RoundTrip(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	mgmtProto.RegisterManagementServiceServer(srv, &agentNetworkSetupServer{key: serverKey})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	client, err := NewClient(context.Background(), lis.Addr().String(), clientKey, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	setup, err := client.GetAgentNetworkSetup(context.Background())
	require.NoError(t, err)
	assert.True(t, setup.Configured)
	assert.Equal(t, "https://violet.eu.proxy.example.com", setup.Endpoint)
	require.Len(t, setup.Providers, 1)
	assert.Equal(t, "anthropic_api", setup.Providers[0].CatalogId)
	assert.Equal(t, []string{"claude-sonnet-4-5"}, setup.Providers[0].Models)
}
