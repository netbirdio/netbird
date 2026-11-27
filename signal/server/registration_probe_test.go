package server

import (
	"context"
	"io"
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
	"github.com/netbirdio/netbird/signal/peer"
)

// startProbeTestSignal serves a real Signal over gRPC and returns a client for it.
func startProbeTestSignal(t *testing.T) proto.SignalExchangeClient {
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

// connectPeer opens a registered stream for id, announcing a registration probe
// when probe is set.
func connectPeer(t *testing.T, client proto.SignalExchangeClient, id string, probe bool) proto.SignalExchange_ConnectStreamClient {
	t.Helper()

	md := metadata.Pairs(proto.HeaderId, id)
	if probe {
		md.Append(proto.HeaderRegistrationProbe, "1")
	}
	ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(context.Background(), md))
	t.Cleanup(cancel)

	stream, err := client.ConnectStream(ctx)
	require.NoError(t, err)
	header, err := stream.Header()
	require.NoError(t, err)
	require.NotEmpty(t, header.Get(proto.HeaderRegistered), "stream must be registered")
	return stream
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

// sendMarker delivers a message to id through Send, ending a check: a stream write
// that Signal wrongly passed on would normally arrive before it.
func sendMarker(t *testing.T, client proto.SignalExchangeClient, id string) {
	t.Helper()
	_, err := client.Send(context.Background(), &proto.EncryptedMessage{Key: id, RemoteKey: id, Body: []byte("marker")})
	require.NoError(t, err)
}

// TestConnectStreamEchoesTheRegistrationProbe covers the probe a client writes to
// release a header held by a proxy: it comes back on the stream it was written to.
func TestConnectStreamEchoesTheRegistrationProbe(t *testing.T) {
	client := startProbeTestSignal(t)
	stream := connectPeer(t, client, "peer-a", true)

	require.NoError(t, stream.Send(&proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("probe")}))
	assert.Equal(t, []byte("probe"), recvWithin(t, stream).Body, "the probe must come back on the stream it was written to")
}

// scriptedStream hands out queued messages, then EOF, and records what is sent.
type scriptedStream struct {
	proto.SignalExchange_ConnectStreamServer
	queued []*proto.EncryptedMessage
	reads  int
	sent   []*proto.EncryptedMessage
}

func (s *scriptedStream) Context() context.Context { return context.Background() }

func (s *scriptedStream) Recv() (*proto.EncryptedMessage, error) {
	s.reads++
	if len(s.queued) == 0 {
		return nil, io.EOF
	}
	msg := s.queued[0]
	s.queued = s.queued[1:]
	return msg, nil
}

func (s *scriptedStream) Send(msg *proto.EncryptedMessage) error {
	s.sent = append(s.sent, msg)
	return nil
}

// TestRegistrationProbeEchoReadsOneMessage pins that the reader stops after the
// first message, so Signal keeps no reader per peer for the life of the stream.
func TestRegistrationProbeEchoReadsOneMessage(t *testing.T) {
	srv, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	stream := &scriptedStream{queued: []*proto.EncryptedMessage{
		{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("probe")},
		{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("second probe")},
	}}

	srv.echoRegistrationProbe(peer.NewPeer("peer-a", stream, func() {}))

	assert.Equal(t, 1, stream.reads, "the reader must stop after the first message")
	require.Len(t, stream.sent, 1, "exactly one echo")
	assert.Equal(t, []byte("probe"), stream.sent[0].Body, "the first probe is the one echoed")
}

// TestConnectStreamDoesNotForwardTheFirstMessage makes sure a first message that
// is not the client's own probe is dropped: forwarding it would skip Send's
// per-message authentication.
func TestConnectStreamDoesNotForwardTheFirstMessage(t *testing.T) {
	client := startProbeTestSignal(t)
	target := connectPeer(t, client, "peer-b", false)

	for _, msg := range []*proto.EncryptedMessage{
		{Key: "peer-a", RemoteKey: "peer-b", Body: []byte("forwarded")},
		{Key: "peer-b", RemoteKey: "peer-b", Body: []byte("spoofed probe")},
	} {
		sender := connectPeer(t, client, "peer-a", true)
		require.NoError(t, sender.Send(msg))
		sendMarker(t, client, "peer-a")
		assert.Equal(t, []byte("marker"), recvWithin(t, sender).Body, "a first message that is not a probe must not be echoed")
	}

	sendMarker(t, client, "peer-b")
	assert.Equal(t, []byte("marker"), recvWithin(t, target).Body, "stream writes must never reach another peer")
}

// TestConnectStreamWithoutProbeIgnoresStreamWrites keeps today's behavior for a
// client that did not announce a probe: nothing is read from its stream.
func TestConnectStreamWithoutProbeIgnoresStreamWrites(t *testing.T) {
	client := startProbeTestSignal(t)
	stream := connectPeer(t, client, "peer-a", false)

	require.NoError(t, stream.Send(&proto.EncryptedMessage{Key: "peer-a", RemoteKey: "peer-a", Body: []byte("probe")}))
	sendMarker(t, client, "peer-a")
	assert.Equal(t, []byte("marker"), recvWithin(t, stream).Body, "a stream write must not be echoed")
}

// TestConnectStreamSurvivesClientCloseSend checks the stream keeps delivering when
// the client closes its side before writing the probe.
func TestConnectStreamSurvivesClientCloseSend(t *testing.T) {
	client := startProbeTestSignal(t)
	stream := connectPeer(t, client, "peer-a", true)

	require.NoError(t, stream.CloseSend())
	sendMarker(t, client, "peer-a")
	assert.Equal(t, []byte("marker"), recvWithin(t, stream).Body, "the stream must still deliver after the client closed its side")
}
