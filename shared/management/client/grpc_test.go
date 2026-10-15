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

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/certposture"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestMaxRecvMsgSize(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected int
	}{
		{name: "unset returns default", envValue: "", expected: defaultMaxRecvMsgSize},
		{name: "valid value", envValue: "10485760", expected: 10485760},
		{name: "non-numeric returns default", envValue: "abc", expected: defaultMaxRecvMsgSize},
		{name: "negative returns default", envValue: "-1", expected: defaultMaxRecvMsgSize},
		{name: "zero returns default", envValue: "0", expected: defaultMaxRecvMsgSize},
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

// TestInfoToMetaData_CarriesCertificateProofs: management verifies the proofs it receives
// in the peer meta, so a field dropped by the mapping fails the certificate check without
// any error on either side.
func TestInfoToMetaData_CarriesCertificateProofs(t *testing.T) {
	info := &system.Info{CertificateProofs: []certposture.Proof{
		{Nonce: []byte("nonce-1"), Chain: [][]byte{[]byte("leaf"), []byte("intermediate")}, SigAlg: "ecdsa-sha256", Signature: []byte("sig-1")},
		{Nonce: []byte("nonce-2"), Chain: [][]byte{[]byte("other")}, SigAlg: "rsa-pss-sha256", Signature: []byte("sig-2")},
	}}

	meta := infoToMetaData(info)

	require.Len(t, meta.GetCertificateProofs(), 2, "every proof reaches the meta")
	first := meta.GetCertificateProofs()[0]
	assert.Equal(t, []byte("nonce-1"), first.GetNonce())
	assert.Equal(t, [][]byte{[]byte("leaf"), []byte("intermediate")}, first.GetChain(), "the whole chain is carried, in order")
	assert.Equal(t, "ecdsa-sha256", first.GetSigAlg())
	assert.Equal(t, []byte("sig-1"), first.GetSignature())
	assert.Equal(t, "rsa-pss-sha256", meta.GetCertificateProofs()[1].GetSigAlg())

	assert.Empty(t, infoToMetaData(&system.Info{}).GetCertificateProofs(), "a device without proofs sends none")
}
