package cmd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

// mockDNSDaemon is a minimal gRPC daemon that only implements FlushDNSCache.
type mockDNSDaemon struct {
	proto.UnimplementedDaemonServiceServer
	flushErr error
}

func (m *mockDNSDaemon) FlushDNSCache(_ context.Context, _ *proto.FlushDNSCacheRequest) (*proto.FlushDNSCacheResponse, error) {
	if m.flushErr != nil {
		return nil, m.flushErr
	}
	return &proto.FlushDNSCacheResponse{}, nil
}

// startMockDaemon starts a gRPC server backed by mock and returns its address.
func startMockDaemon(t *testing.T, mock *mockDNSDaemon) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	proto.RegisterDaemonServiceServer(s, mock)
	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("mock daemon serve error: %v", err)
		}
	}()
	t.Cleanup(s.Stop)

	return "tcp://" + lis.Addr().String()
}

func TestDNSFlushCacheCmd_Success(t *testing.T) {
	addr := startMockDaemon(t, &mockDNSDaemon{})

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"dns", "flush-cache", "--daemon-addr", addr, "--log-file", ""})

	err := rootCmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "DNS cache flushed successfully")
}

func TestDNSFlushCacheCmd_DaemonError(t *testing.T) {
	daemonErr := gstatus.Error(codes.Internal, "flush failed")
	addr := startMockDaemon(t, &mockDNSDaemon{flushErr: daemonErr})

	rootCmd.SetArgs([]string{"dns", "flush-cache", "--daemon-addr", addr, "--log-file", ""})

	err := rootCmd.Execute()
	assert.Error(t, err)
}

func TestDNSFlushCacheCmd_NoArgs(t *testing.T) {
	addr := startMockDaemon(t, &mockDNSDaemon{})

	rootCmd.SetArgs([]string{"dns", "flush-cache", "unexpected-arg", "--daemon-addr", addr, "--log-file", ""})

	err := rootCmd.Execute()
	assert.Error(t, err)
}
