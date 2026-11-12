package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

// signalTestClient is a GrpcClient started by a test, with the context that
// stops its receive loop and the channel that reports the loop has left.
type signalTestClient struct {
	*GrpcClient
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// receive starts the receive loop in the background. The test cleanup
// cancels the context and waits on done, so no reconnect goroutine
// outlives the test.
func (c *signalTestClient) receive(handler func(msg *sigProto.Message) error) {
	go func() {
		defer close(c.done)
		_ = c.Receive(c.ctx, handler)
	}()
}

func newSignalTestClient(t *testing.T, addr string, key wgtypes.Key) *signalTestClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	c := &signalTestClient{GrpcClient: client, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	t.Cleanup(func() {
		// Stop the receive loop before Close, so the two never overlap.
		cancel()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Error("signal client receive loop did not stop")
		}
		assert.NoError(t, c.Close())
	})
	return c
}

func startSignal(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := grpc.NewServer()
	srv, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	sigProto.RegisterSignalExchangeServer(s, srv)
	go func() {
		// Serve returns when the test stops the server; that is the normal
		// end of a test, not a failure.
		_ = s.Serve(lis)
	}()
	t.Cleanup(func() {
		s.Stop()
		_ = lis.Close() // already closed by Stop
	})
	return lis.Addr().String()
}

func newRawSignalClient(t *testing.T, addr string) sigProto.SignalExchangeClient {
	t.Helper()
	conn, err := grpc.DialContext(context.Background(), addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    3 * time.Second,
			Timeout: 2 * time.Second,
		}))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return sigProto.NewSignalExchangeClient(conn)
}

func TestGrpcClient_ExchangeMessages(t *testing.T) {
	addr := startSignal(t)

	var msgReceived sync.WaitGroup
	msgReceived.Add(2)

	var payloadReceivedOnA string
	var payloadReceivedOnB string
	var featuresSupportedReceivedOnA []uint32
	var featuresSupportedReceivedOnB []uint32
	var sendErr error

	// connect PeerA to Signal
	keyA, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	clientA := newSignalTestClient(t, addr, keyA)
	clientA.receive(func(msg *sigProto.Message) error {
		payloadReceivedOnA = msg.GetBody().GetPayload()
		featuresSupportedReceivedOnA = msg.GetBody().GetFeaturesSupported()
		msgReceived.Done()
		return nil
	})
	ctxA, cancelA := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelA()
	clientA.WaitStreamConnected(ctxA)
	require.True(t, clientA.StreamConnected())

	// connect PeerB to Signal
	keyB, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	clientB := newSignalTestClient(t, addr, keyB)
	clientB.receive(func(msg *sigProto.Message) error {
		payloadReceivedOnB = msg.GetBody().GetPayload()
		featuresSupportedReceivedOnB = msg.GetBody().GetFeaturesSupported()
		sendErr = clientB.Send(&sigProto.Message{
			Key:       keyB.PublicKey().String(),
			RemoteKey: keyA.PublicKey().String(),
			Body:      &sigProto.Body{Payload: "pong"},
		})
		msgReceived.Done()
		return nil
	})
	ctxB, cancelB := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelB()
	clientB.WaitStreamConnected(ctxB)
	require.True(t, clientB.StreamConnected())

	// PeerA initiates ping-pong
	err = clientA.Send(&sigProto.Message{
		Key:       keyA.PublicKey().String(),
		RemoteKey: keyB.PublicKey().String(),
		Body:      &sigProto.Body{Payload: "ping", FeaturesSupported: []uint32{DirectCheck}},
	})
	require.NoError(t, err)

	if waitTimeout(&msgReceived, 3*time.Second) {
		t.Fatal("test timed out on waiting for peers to exchange messages")
	}
	require.NoError(t, sendErr, "PeerB failed sending a message to PeerA")

	assert.Equal(t, "pong", payloadReceivedOnA)
	assert.Equal(t, "ping", payloadReceivedOnB)
	assert.Nil(t, featuresSupportedReceivedOnA)
	assert.ElementsMatch(t, []uint32{DirectCheck}, featuresSupportedReceivedOnB)
}

func TestGrpcClient_ConnectStream(t *testing.T) {
	addr := startSignal(t)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	client := newSignalTestClient(t, addr, key)
	client.receive(func(msg *sigProto.Message) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client.WaitStreamConnected(ctx)
	assert.True(t, client.StreamConnected())
}

func TestGrpcClient_RawConnectWithoutIDFails(t *testing.T) {
	addr := startSignal(t)

	client := newRawSignalClient(t, addr)
	stream, err := client.ConnectStream(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stream)

	_, err = stream.Recv()
	assert.Error(t, err)
}

func TestGrpcClient_RawConnectWithID(t *testing.T) {
	addr := startSignal(t)

	md := metadata.New(map[string]string{sigProto.HeaderId: "peer"})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	client := newRawSignalClient(t, addr)
	stream, err := client.ConnectStream(ctx)

	assert.NotNil(t, stream)
	assert.NoError(t, err)
}

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}
