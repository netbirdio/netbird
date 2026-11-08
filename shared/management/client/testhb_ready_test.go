package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/testhb"
)

type readyMgmtServer struct {
	proto.UnimplementedManagementServiceServer
}

func (readyMgmtServer) Sync(_ *proto.EncryptedMessage, stream proto.ManagementService_SyncServer) error {
	<-stream.Context().Done()
	return nil
}

// syncStateAtValue starts a local Management server, opens the Sync stream on a
// fresh (Idle) connection and returns the connection state seen when the value
// is built.
func syncStateAtValue(t *testing.T) connectivity.State {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterManagementServiceServer(srv, readyMgmtServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.Equal(t, connectivity.Idle, conn.GetState())

	var seen connectivity.State
	prev := testHBValue
	testHBValue = func(svc, key string) (string, bool) {
		seen = conn.GetState()
		return prev(svc, key)
	}
	t.Cleanup(func() { testHBValue = prev })

	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: clientKey, realClient: proto.NewManagementServiceClient(conn), conn: conn}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.connectToSyncStream(ctx, serverKey.PublicKey(), nil)
	require.NoError(t, err)
	return seen
}

func TestSyncDynamicWaitsForReady(t *testing.T) {
	t.Setenv(testhb.EnvDynamic, "1")
	require.Equal(t, connectivity.Ready, syncStateAtValue(t))
}

func TestSyncStockDoesNotWait(t *testing.T) {
	t.Setenv(testhb.EnvDynamic, "")
	require.Equal(t, connectivity.Idle, syncStateAtValue(t))
}

func TestWaitConnReadyReturnsOnContextEnd(t *testing.T) {
	conn, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	waitConnReady(ctx, conn)
	require.Less(t, time.Since(start), 2*time.Second)
	require.NotEqual(t, connectivity.Ready, conn.GetState())
}
