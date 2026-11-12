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
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/shared/testhb"
)

type readySignalServer struct {
	proto.UnimplementedSignalExchangeServer
}

func (readySignalServer) ConnectStream(stream proto.SignalExchange_ConnectStreamServer) error {
	if err := stream.SendHeader(metadata.Pairs(proto.HeaderRegistered, "1")); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

// stateAtValue starts a local Signal server, opens connect on a fresh (Idle)
// connection and returns the connection state seen when the value is built.
func stateAtValue(t *testing.T) connectivity.State {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterSignalExchangeServer(srv, readySignalServer{})
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

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{
		key:                       key,
		realClient:                proto.NewSignalExchangeClient(conn),
		signalConn:                conn,
		registrationTimeout:       defaultRegistrationTimeout,
		registrationProbeInterval: defaultRegistrationProbeInterval,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.connect(ctx, cancel, key.PublicKey().String())
	require.NoError(t, err)
	return seen
}

func TestConnectDynamicWaitsForReady(t *testing.T) {
	t.Setenv(testhb.EnvDynamic, "1")
	require.Equal(t, connectivity.Ready, stateAtValue(t))
}

func TestConnectStockDoesNotWait(t *testing.T) {
	t.Setenv(testhb.EnvDynamic, "")
	require.Equal(t, connectivity.Idle, stateAtValue(t))
}

func TestWaitConnReadyReturnsOnContextEnd(t *testing.T) {
	// nothing listens here, so the connection never gets Ready
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

func TestWaitConnReadyReturnsOnShutdown(t *testing.T) {
	conn, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	done := make(chan struct{})
	go func() { waitConnReady(context.Background(), conn); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitConnReady did not return on Shutdown")
	}
}
