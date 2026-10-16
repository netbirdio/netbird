package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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
