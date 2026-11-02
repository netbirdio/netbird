package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"

	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

// stallingSignalServer holds the first ConnectStream open without ever sending
// the registration header, while the transport keeps answering keepalive pings.
// Later streams go to the real server. This is what a responder in front of or
// inside Signal looks like when it accepts a stream and never answers it.
type stallingSignalServer struct {
	*server.Server
	stalled atomic.Bool
	held    chan struct{}
}

func (s *stallingSignalServer) ConnectStream(stream sigProto.SignalExchange_ConnectStreamServer) error {
	if s.stalled.CompareAndSwap(false, true) {
		close(s.held)
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	return s.Server.ConnectStream(stream)
}

// TestReceiveRetriesWhenRegistrationHeaderNeverArrives reproduces a client stuck
// forever waiting for the registration header of a stream the server side never
// answers: the receive watchdog only starts after registration, so nothing ended
// the wait and Signal never came back until the daemon was restarted. The client
// must give up on the silent stream and register on a new one.
func TestReceiveRetriesWhenRegistrationHeaderNeverArrives(t *testing.T) {
	realServer, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	stalling := &stallingSignalServer{Server: realServer, held: make(chan struct{})}
	addr := serveTestSignalExchange(t, stalling)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.registrationTimeout = 200 * time.Millisecond

	// Stop Receive before Close runs (cleanups are LIFO), so the two never overlap.
	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		_ = client.Receive(ctx, func(*sigProto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-receiveDone
	})

	select {
	case <-stalling.held:
	case <-time.After(5 * time.Second):
		t.Fatal("first stream did not reach the stalling server")
	}

	streamReady := make(chan struct{})
	go func() {
		client.WaitStreamConnected(ctx)
		close(streamReady)
	}()
	select {
	case <-streamReady:
	case <-time.After(5 * time.Second):
		t.Fatal("client never registered after the first stream went unanswered")
	}
	require.True(t, client.StreamConnected(), "client should report a registered stream")
}

// headerBufferingStream withholds the response headers until the first message
// is sent, as AWS ALB and CloudFront do with gRPC streams: a stream that only
// sends headers never delivers them.
type headerBufferingStream struct {
	sigProto.SignalExchange_ConnectStreamServer
	mu     sync.Mutex
	header metadata.MD
	sent   bool
}

func (s *headerBufferingStream) SendHeader(md metadata.MD) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.header = md
	return nil
}

func (s *headerBufferingStream) Send(msg *sigProto.EncryptedMessage) error {
	s.mu.Lock()
	if !s.sent {
		s.sent = true
		if err := s.SignalExchange_ConnectStreamServer.SendHeader(s.header); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()
	return s.SignalExchange_ConnectStreamServer.Send(msg)
}

type headerBufferingSignalServer struct {
	*server.Server
	dropFirstSend atomic.Bool
}

// Send can drop the first message while still acknowledging it, as the server
// does for a heartbeat that arrives before the stream is registered.
func (s *headerBufferingSignalServer) Send(ctx context.Context, msg *sigProto.EncryptedMessage) (*sigProto.EncryptedMessage, error) {
	if s.dropFirstSend.CompareAndSwap(true, false) {
		return &sigProto.EncryptedMessage{}, nil
	}
	return s.Server.Send(ctx, msg)
}

func (s *headerBufferingSignalServer) ConnectStream(stream sigProto.SignalExchange_ConnectStreamServer) error {
	return s.Server.ConnectStream(&headerBufferingStream{SignalExchange_ConnectStreamServer: stream})
}

// TestReceiveRegistersWhenProxyBuffersHeaders covers a proxy that delivers the
// registration header only together with the first message. With no peer
// sending anything, the client must produce that message itself instead of
// timing out on every attempt.
func TestReceiveRegistersWhenProxyBuffersHeaders(t *testing.T) {
	t.Run("first heartbeat delivered", func(t *testing.T) {
		testRegistersBehindHeaderBuffering(t, false)
	})
	// A heartbeat that loses the race with the registration is dropped; the
	// next one must still release the header.
	t.Run("first heartbeat dropped", func(t *testing.T) {
		testRegistersBehindHeaderBuffering(t, true)
	})
}

func testRegistersBehindHeaderBuffering(t *testing.T, dropFirstSend bool) {
	t.Helper()
	realServer, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	srv := &headerBufferingSignalServer{Server: realServer}
	srv.dropFirstSend.Store(dropFirstSend)
	addr := serveTestSignalExchange(t, srv)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.registrationTimeout = 2 * time.Second
	client.registrationProbeInterval = 200 * time.Millisecond

	// Stop Receive before Close runs (cleanups are LIFO), so the two never overlap.
	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		_ = client.Receive(ctx, func(*sigProto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-receiveDone
	})

	streamReady := make(chan struct{})
	go func() {
		client.WaitStreamConnected(ctx)
		close(streamReady)
	}()
	// Registering within the first stream's timeout proves the heartbeats
	// released the header, not a retry on a new stream.
	select {
	case <-streamReady:
	case <-time.After(client.registrationTimeout):
		t.Fatal("client never registered while the proxy withheld the header")
	}
	require.True(t, client.StreamConnected(), "client should report a registered stream")
}
