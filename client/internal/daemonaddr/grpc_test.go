package daemonaddr

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

func TestMaxRecvMsgSize(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected int
	}{
		{name: "unset returns default", envValue: "", expected: defaultMaxRecvMsgSize},
		{name: "non-numeric returns default", envValue: "abc", expected: defaultMaxRecvMsgSize},
		{name: "negative returns default", envValue: "-1", expected: defaultMaxRecvMsgSize},
		{name: "zero returns default", envValue: "0", expected: defaultMaxRecvMsgSize},
		{name: "valid value is used", envValue: "33554432", expected: 33554432},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set first so the previous value is restored on cleanup, then unset to
			// exercise the absent case.
			t.Setenv(EnvMaxRecvMsgSize, tc.envValue)
			if tc.envValue == "" {
				require.NoError(t, os.Unsetenv(EnvMaxRecvMsgSize), "unset the override")
			}

			assert.Equal(t, tc.expected, MaxRecvMsgSize(), "max receive message size")
		})
	}
}

// bigStatusServer answers Status with a response larger than gRPC's 4 MB default
// receive limit, which is what a detailed status on a large network looks like.
type bigStatusServer struct {
	proto.UnimplementedDaemonServiceServer
	payload string
}

func (s *bigStatusServer) Status(context.Context, *proto.StatusRequest) (*proto.StatusResponse, error) {
	return &proto.StatusResponse{Status: s.payload}, nil
}

func startBigStatusServer(t *testing.T, payload string) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen on loopback")

	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, &bigStatusServer{payload: payload})
	go func() {
		_ = srv.Serve(listener)
	}()
	t.Cleanup(srv.Stop)

	return "tcp://" + listener.Addr().String()
}

func TestDialTargetAcceptsAStatusOverTheGrpcDefault(t *testing.T) {
	payload := strings.Repeat("x", 5*1024*1024)
	addr := startBigStatusServer(t, payload)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target, opts := DialTarget(addr)
	conn, err := grpc.NewClient(target, opts...)
	require.NoError(t, err, "dial the daemon")
	t.Cleanup(func() { _ = conn.Close() })

	resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{})
	require.NoError(t, err, "a detailed status must not be rejected for its size")
	assert.Len(t, resp.GetStatus(), len(payload), "the whole response must arrive")
}

// TestDialTargetRaisesTheDefaultLimit is the negative control: the same response
// over a connection carrying gRPC's own defaults is refused, which is the failure
// reported by `netbird status -d` on a large deployment.
func TestDialTargetRaisesTheDefaultLimit(t *testing.T) {
	payload := strings.Repeat("x", 5*1024*1024)
	addr := startBigStatusServer(t, payload)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(
		strings.TrimPrefix(addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "dial with the library defaults")
	t.Cleanup(func() { _ = conn.Close() })

	_, err = proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{})
	require.Error(t, err, "the library default must reject this response")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "gRPC rejects an oversized message")
}
