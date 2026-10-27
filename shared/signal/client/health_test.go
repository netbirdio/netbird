package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
)

type recordingNotifier struct {
	mu        sync.Mutex
	connected bool
}

func (n *recordingNotifier) MarkSignalDisconnected(error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.connected = false
}

func (n *recordingNotifier) MarkSignalConnected() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.connected = true
}

func (n *recordingNotifier) isConnected() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.connected
}

// TestIsHealthyRequiresRegisteredStream covers the status reporting half of a
// stuck registration: the gRPC connection to Signal is up but no stream is
// registered, so no peer can reach this client. The health check used to look
// at the connection only, reporting Signal as connected throughout.
func TestIsHealthyRequiresRegisteredStream(t *testing.T) {
	addr := startTestSignalServer(t)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	notifier := &recordingNotifier{}
	client.SetConnStateListener(notifier)

	assert.False(t, client.IsHealthy(), "no registered stream must not be reported healthy")
	assert.False(t, notifier.isConnected(), "no registered stream must not mark Signal connected")

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
	select {
	case <-streamReady:
	case <-time.After(5 * time.Second):
		t.Fatal("signal stream did not connect within timeout")
	}

	assert.True(t, client.IsHealthy(), "a registered stream on a usable connection must be healthy")
	assert.True(t, notifier.isConnected(), "a registered stream must mark Signal connected")
}

// TestIsHealthyConnectingWithoutStream covers the window while the connection is
// still being established: a TCP listener that accepts but never speaks HTTP/2
// keeps the channel in Connecting, and with no registered stream the client
// cannot receive anything yet, so it must not be reported healthy.
func TestIsHealthyConnectingWithoutStream(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var accepted []net.Conn
	t.Cleanup(func() {
		_ = lis.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range accepted {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	conn.Connect()
	require.Eventually(t, func() bool { return conn.GetState() == connectivity.Connecting }, 5*time.Second, 10*time.Millisecond,
		"channel should be stuck connecting to a listener that never answers")

	client := &GrpcClient{signalConn: conn, status: StreamDisconnected}
	assert.False(t, client.IsHealthy(), "a connecting channel with no registered stream must not be reported healthy")
}
