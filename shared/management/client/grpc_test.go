package client

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestMaxRecvMsgSize(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected int
	}{
		{name: "unset returns 0", envValue: "", expected: 0},
		{name: "valid value", envValue: "10485760", expected: 10485760},
		{name: "non-numeric returns 0", envValue: "abc", expected: 0},
		{name: "negative returns 0", envValue: "-1", expected: 0},
		{name: "zero returns 0", envValue: "0", expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvMaxRecvMsgSize, tt.envValue)
			if tt.envValue == "" {
				os.Unsetenv(EnvMaxRecvMsgSize)
			}
			assert.Equal(t, tt.expected, MaxRecvMsgSize())
		})
	}
}

// largeSyncServer implements just the Sync RPC, returning a response larger than the default 4MB limit.
type largeSyncServer struct {
	mgmtProto.UnimplementedManagementServiceServer
	responseSize int
}

func (s *largeSyncServer) GetServerKey(_ context.Context, _ *mgmtProto.Empty) (*mgmtProto.ServerKeyResponse, error) {
	// Return a response with a large WiretrusteeConfig to exceed the default limit.
	padding := strings.Repeat("x", s.responseSize)
	return &mgmtProto.ServerKeyResponse{
		Key: padding,
	}, nil
}

func TestMaxRecvMsgSizeIntegration(t *testing.T) {
	const payloadSize = 5 * 1024 * 1024 // 5MB, exceeds 4MB default

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	mgmtProto.RegisterManagementServiceServer(srv, &largeSyncServer{responseSize: payloadSize})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	t.Run("default limit rejects large message", func(t *testing.T) {
		conn, err := grpc.NewClient(
			lis.Addr().String(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := mgmtProto.NewManagementServiceClient(conn)
		_, err = client.GetServerKey(context.Background(), &mgmtProto.Empty{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "received message larger than max")
	})

	t.Run("increased limit accepts large message", func(t *testing.T) {
		conn, err := grpc.NewClient(
			lis.Addr().String(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := mgmtProto.NewManagementServiceClient(conn)
		resp, err := client.GetServerKey(context.Background(), &mgmtProto.Empty{})
		require.NoError(t, err)
		assert.Len(t, resp.Key, payloadSize)
	})
}
