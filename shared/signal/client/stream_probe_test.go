package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

// probePathSignalServer is a real Signal whose Send path can be broken and which
// can pretend to predate the stream echo.
type probePathSignalServer struct {
	*server.Server
	rejectSend bool
	noEcho     bool
	streams    atomic.Int32
}

func (s *probePathSignalServer) Send(ctx context.Context, msg *sigProto.EncryptedMessage) (*sigProto.EncryptedMessage, error) {
	if s.rejectSend {
		return nil, status.Error(codes.Unavailable, "send path overloaded")
	}
	return s.Server.Send(ctx, msg)
}

func (s *probePathSignalServer) ConnectStream(stream sigProto.SignalExchange_ConnectStreamServer) error {
	s.streams.Add(1)
	if s.noEcho {
		md, _ := metadata.FromIncomingContext(stream.Context())
		md = md.Copy()
		md.Delete(sigProto.HeaderStreamEcho)
		stream = &incomingMDStream{SignalExchange_ConnectStreamServer: stream, ctx: metadata.NewIncomingContext(stream.Context(), md)}
	}
	return s.Server.ConnectStream(stream)
}

type incomingMDStream struct {
	sigProto.SignalExchange_ConnectStreamServer
	ctx context.Context
}

func (s *incomingMDStream) Context() context.Context { return s.ctx }

// countWatchdogProbes runs a client with a fast watchdog against srv and returns
// a counter of the client's own heartbeats it received back.
func countWatchdogProbes(t *testing.T, srv *probePathSignalServer) *atomic.Int32 {
	t.Helper()
	addr := serveTestSignalExchange(t, srv)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.watchdog = watchdogTimings{interval: 10 * time.Millisecond}

	var probes atomic.Int32
	self := key.PublicKey().String()
	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		_ = client.Receive(ctx, func(msg *sigProto.Message) error {
			if msg.GetBody().GetType() == sigProto.Body_HEARTBEAT && msg.GetKey() == self {
				probes.Add(1)
			}
			return nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-receiveDone
	})
	return &probes
}

// TestWatchdogProbesOnTheStreamItGuards reproduces the outage shape: the stream is
// healthy but the Send path rejects calls. Probing through Send can never succeed
// there; a probe echoed on the stream proves the stream alive and keeps it.
func TestWatchdogProbesOnTheStreamItGuards(t *testing.T) {
	realServer, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	srv := &probePathSignalServer{Server: realServer, rejectSend: true}
	probes := countWatchdogProbes(t, srv)

	require.Eventually(t, func() bool { return probes.Load() >= 3 }, 5*time.Second, 5*time.Millisecond,
		"watchdog probes must come back on the stream while Send is failing")
	assert.Equal(t, int32(1), srv.streams.Load(), "a healthy stream must not be reconnected")
}

// TestWatchdogFallsBackToSendWithoutEcho covers a Signal that predates the echo:
// it never confirms it, so the client keeps probing through Send.
func TestWatchdogFallsBackToSendWithoutEcho(t *testing.T) {
	realServer, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	srv := &probePathSignalServer{Server: realServer, noEcho: true}
	probes := countWatchdogProbes(t, srv)

	require.Eventually(t, func() bool { return probes.Load() >= 3 }, 5*time.Second, 5*time.Millisecond,
		"watchdog probes must come back through Send when Signal has no echo")
	assert.Equal(t, int32(1), srv.streams.Load(), "a healthy stream must not be reconnected")
}
