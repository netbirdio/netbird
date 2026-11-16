package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/shared/alignedhb"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// swapConn makes conn the connection of c, dialed with keepalive time ka.
func swapConn(c *GrpcClient, conn *grpc.ClientConn, ka time.Duration) {
	c.conn.Swap(conn, sigProto.NewSignalExchangeClient(conn), ka)
}

func lazySignalConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///signal.invalid:443", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newSignalRedialClient(t *testing.T, addr string) (*GrpcClient, *atomic.Int32) {
	t.Helper()
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.SignalComponent, addr) })
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key, addr: addr, ctx: context.Background()}
	swapConn(c, lazySignalConn(t), 70*time.Second)
	var redials atomic.Int32
	c.dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) {
		redials.Add(1)
		return lazySignalConn(t), 30 * time.Second, nil
	}
	return c, &redials
}

// Any answer, with or without a phase, shows a server that supports the
// aligned heartbeat: no redial, and the mark is cleared.
func TestSignalAnswerNoRedial(t *testing.T) {
	c, redials := newSignalRedialClient(t, "signal-aligned.example:443")
	nbgrpc.MarkStock(wsproxy.SignalComponent, c.addr)
	key := c.key.PublicKey().String()

	header := metadata.Pairs(alignedhb.MetadataKey, alignedhb.PendingAnswerValue(time.Minute))
	c.applyAlignedAnswer(header, &blockingSender{release: make(chan struct{})}, key, 0)
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, redials.Load(), "an answer must not redial")
	assert.True(t, nbgrpc.MarkStock(wsproxy.SignalComponent, c.addr), "the answer cleared the mark")
}

// End to end on a server without the aligned heartbeat: the stock answer
// redials, the stream loop reconnects on the new connection instead of taking
// the closed one for a shutdown, and the next stream does not redial again.
func TestSignalStockRedialReconnectsStream(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	addr := startTestSignalServer(t)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.SignalComponent, addr) })
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	// This build does not ask for the aligned heartbeat at dial time; pretend
	// the connection was dialed with the aligned keepalive.
	c.conn.Swap(c.conn.Conn(), c.conn.Client(), 70*time.Second)
	first := c.conn.Conn()

	receiveErr := make(chan error, 1)
	go func() { receiveErr <- c.Receive(ctx, func(*sigProto.Message) error { return nil }) }()
	// Close races with a running receive loop, so end the loop first.
	stopped := false
	stopReceive := func() {
		if !stopped {
			stopped = true
			cancel()
			if err := <-receiveErr; err != nil {
				assert.True(t, errors.Is(err, context.Canceled), "receive loop ended with %v", err)
			}
		}
	}
	t.Cleanup(stopReceive)

	require.Eventually(t, func() bool { return c.conn.Conn() != first }, 15*time.Second, 20*time.Millisecond,
		"the stock answer must redial")
	require.Eventually(t, func() bool { return c.StreamConnected() && c.Ready() }, 15*time.Second, 20*time.Millisecond,
		"the stream must reconnect on the new connection")
	second := c.conn.Conn()
	time.Sleep(500 * time.Millisecond)
	assert.Same(t, second, c.conn.Conn(), "the second stock stream must not redial again")
	select {
	case err := <-receiveErr:
		stopped = true
		t.Fatalf("receive loop ended: %v", err)
	default:
	}
	stopReceive()
}

// Self-hosted Management and Signal can share an address. A Signal answer must
// leave the Management mark in place, or the next Management connection would
// dial with the aligned keepalive and redial again.
func TestSignalAnswerKeepsManagementMark(t *testing.T) {
	const addr = "nb-shared.example:443"
	c, _ := newSignalRedialClient(t, addr)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.ManagementComponent, addr) })
	require.True(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, addr))

	header := metadata.Pairs(alignedhb.MetadataKey, alignedhb.PendingAnswerValue(time.Minute))
	c.applyAlignedAnswer(header, &blockingSender{release: make(chan struct{})}, c.key.PublicKey().String(), 0)
	assert.False(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, addr), "the Management mark must stay")
}
