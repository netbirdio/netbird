package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

// startEchoTestSignal serves a real Signal over gRPC and returns a client for it.
func startEchoTestSignal(t *testing.T) proto.SignalExchangeClient {
	t.Helper()

	srv, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer()
	proto.RegisterSignalExchangeServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return proto.NewSignalExchangeClient(conn)
}

// connectPeer opens a registered stream for id and returns it with its header.
func connectPeer(t *testing.T, client proto.SignalExchangeClient, id string, echo bool) (proto.SignalExchange_ConnectStreamClient, metadata.MD) {
	t.Helper()

	md := metadata.Pairs(proto.HeaderId, id)
	if echo {
		md.Append(proto.HeaderStreamEcho, "1")
	}
	ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), md))
	t.Cleanup(cancel)

	stream, err := client.ConnectStream(ctx)
	require.NoError(t, err)
	header, err := stream.Header()
	require.NoError(t, err)
	require.NotEmpty(t, header.Get(proto.HeaderRegistered), "stream must be registered")
	return stream, header
}

// recvWithin reads one message from stream, failing the test after the deadline.
func recvWithin(t *testing.T, stream proto.SignalExchange_ConnectStreamClient) *proto.EncryptedMessage {
	t.Helper()

	type result struct {
		msg *proto.EncryptedMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := stream.Recv()
		ch <- result{msg, err}
	}()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.msg
	case <-time.After(5 * time.Second):
		t.Fatal("no message on the stream")
		return nil
	}
}

func TestConnectStreamEchoesOwnProbes(t *testing.T) {
	client := startEchoTestSignal(t)
	stream, header := connectPeer(t, client, "peer-a", true)
	assert.Equal(t, []string{"1"}, header.Get(proto.HeaderStreamEcho), "Signal must confirm the echo")

	probe := &proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("stream probe")}
	require.NoError(t, stream.Send(probe))

	echoed := recvWithin(t, stream)
	assert.Equal(t, probe.Body, echoed.Body, "the probe must come back on the stream it was written to")
}

// TestConnectStreamDoesNotForward makes sure a message written on the stream for
// another peer is dropped: forwarding it would skip Send's per-message auth.
func TestConnectStreamDoesNotForward(t *testing.T) {
	client := startEchoTestSignal(t)
	sender, _ := connectPeer(t, client, "peer-a", true)
	target, _ := connectPeer(t, client, "peer-b", true)

	require.NoError(t, sender.Send(&proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-b", Body: []byte("forwarded")}))
	require.NoError(t, sender.Send(&proto.EncryptedMessage{Key: "peer-b", RemoteKey: "peer-b", Body: []byte("spoofed probe")}))

	// A message through Send marks the point after the stream writes were handled.
	_, err := client.Send(context.Background(), &proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-b", Body: []byte("marker")})
	require.NoError(t, err)
	assert.Equal(t, []byte("marker"), recvWithin(t, target).Body, "stream writes must never reach another peer")

	// Neither write came back to the sender either: its own probe is next.
	require.NoError(t, sender.Send(&proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("probe")}))
	assert.Equal(t, []byte("probe"), recvWithin(t, sender).Body, "only the sender's own probe is echoed")
}

// TestConnectStreamWithoutEchoIgnoresStreamWrites keeps today's behavior for a
// client that did not ask: no confirmation and nothing read from the stream.
func TestConnectStreamWithoutEchoIgnoresStreamWrites(t *testing.T) {
	client := startEchoTestSignal(t)
	stream, header := connectPeer(t, client, "peer-a", false)
	assert.Empty(t, header.Get(proto.HeaderStreamEcho), "Signal must not offer an echo it was not asked for")

	require.NoError(t, stream.Send(&proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("stream probe")}))
	_, err := client.Send(context.Background(), &proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("unary probe")})
	require.NoError(t, err)

	assert.Equal(t, []byte("unary probe"), recvWithin(t, stream).Body, "a stream write must not be echoed")
}

// TestConnectStreamEchoSurvivesClientCloseSend checks the reader stops on EOF and
// the stream keeps delivering: the reader removed in #3820 spun on EOF.
func TestConnectStreamEchoSurvivesClientCloseSend(t *testing.T) {
	client := startEchoTestSignal(t)
	stream, _ := connectPeer(t, client, "peer-a", true)

	require.NoError(t, stream.CloseSend())
	_, err := client.Send(context.Background(), &proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("after close")})
	require.NoError(t, err)
	assert.Equal(t, []byte("after close"), recvWithin(t, stream).Body, "the stream must still deliver after the client closed its side")
}
