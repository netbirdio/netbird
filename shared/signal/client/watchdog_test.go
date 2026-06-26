package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

func startTestSignalServer(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	srv, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	sigProto.RegisterSignalExchangeServer(s, srv)

	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	return lis.Addr().String()
}

// TestReceiveProbeRoundTrips verifies that the watchdog's self-addressed heartbeat
// is routed back to the same client through the signal server. This round-trip is
// what lets the watchdog confirm the receive direction is still delivering.
func TestReceiveProbeRoundTrips(t *testing.T) {
	addr := startTestSignalServer(t)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	received := make(chan struct{}, 1)
	go func() {
		_ = client.Receive(ctx, func(msg *sigProto.Message) error {
			if msg.GetBody().GetType() == sigProto.Body_HEARTBEAT && msg.GetKey() == key.PublicKey().String() {
				select {
				case received <- struct{}{}:
				default:
				}
			}
			return nil
		})
	}()

	streamReady := make(chan struct{})
	go func() {
		client.WaitStreamConnected(ctx)
		close(streamReady)
	}()
	select {
	case <-streamReady:
	case <-time.After(5 * time.Second):
		t.Fatal("signal stream did not connect within timeout")
	}

	require.NoError(t, client.sendReceiveProbe())

	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("self-addressed heartbeat did not round-trip back through the signal server")
	}
}
