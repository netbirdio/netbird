package client

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// swapConn makes conn the connection of c, dialed with keepalive time ka.
func swapConn(c *GrpcClient, conn *grpc.ClientConn, ka time.Duration) {
	c.conn.Swap(conn, proto.NewManagementServiceClient(conn), ka)
}

func lazyConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///mgmt.invalid:443", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// newRedialClient returns a client whose connection was dialed with the
// aligned keepalive, and the count of redials.
func newRedialClient(t *testing.T, addr string) (*GrpcClient, *atomic.Int32) {
	t.Helper()
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.ManagementComponent, addr) })
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key, serverURL: addr, ctx: context.Background()}
	swapConn(c, lazyConn(t), 70*time.Second)
	var redials atomic.Int32
	c.dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) {
		redials.Add(1)
		return lazyConn(t), 30 * time.Second, nil
	}
	return c, &redials
}

// stockSync is a sync response from an old server: a peer config without the
// aligned heartbeat field.
var stockSync = &proto.SyncResponse{PeerConfig: &proto.PeerConfig{}}

// An aligned answer gives no redial and clears the mark for the next dial.
func TestAlignedAnswerNoRedial(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	c, redials := newRedialClient(t, "mgmt-aligned.example:443")
	nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL)

	c.applyAlignedConfig(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1000})
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, redials.Load(), "an aligned answer must not redial")
	assert.True(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL), "the aligned answer cleared the mark")
}

// receiveStream runs one Sync stream of c that delivers resps in order.
func receiveStream(t *testing.T, c *GrpcClient, resps ...*proto.SyncResponse) {
	t.Helper()
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	stream := &fakeSyncStream{}
	for _, resp := range resps {
		stream.msgs = append(stream.msgs, encryptForClient(t, serverKey, c.key, resp))
	}
	err = c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(*proto.SyncResponse) error { return nil })
	require.ErrorIs(t, err, io.EOF)
}

// alignedSync is a first response that confirms the aligned heartbeat.
var alignedSync = &proto.SyncResponse{PeerConfig: &proto.PeerConfig{
	AlignedHeartbeat: &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1000},
}}

// Management sets the aligned field only in the first response of a stream. A
// later network map update without it is no stock answer.
func TestAlignedStreamLaterUpdateNoStock(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	c, redials := newRedialClient(t, "mgmt-later.example:443")

	receiveStream(t, c, alignedSync, stockSync)
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, redials.Load(), "a later update without the aligned field must not redial")
	assert.True(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL), "a later update must not mark the server stock")
	answer, ok := c.alignedHeartbeat()
	assert.True(t, ok, "the aligned answer must stay")
	assert.Equal(t, time.Minute, answer.Period, "the aligned period must stay")
}

// A stock first response still marks the server and redials once, also when
// more updates follow on the stream.
func TestStockStreamFirstResponseRedials(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	c, redials := newRedialClient(t, "mgmt-first.example:443")

	receiveStream(t, c, stockSync, stockSync)
	require.Eventually(t, func() bool { return redials.Load() == 1 }, time.Second, 5*time.Millisecond,
		"a stock first response must redial once")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), redials.Load(), "later updates must not redial again")
	assert.False(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL), "the server is marked stock")
}

// Each stream is judged by its own first response: a stock stream after an
// aligned one marks the server and redials, an aligned stream after it clears
// the mark again.
func TestNewStreamJudgedByOwnFirstResponse(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	c, redials := newRedialClient(t, "mgmt-restream.example:443")

	receiveStream(t, c, alignedSync, stockSync)
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, redials.Load(), "the aligned stream must not redial")

	c.setAlignedAnswer(nil) // connectToSyncStream resets the answer of a new stream
	receiveStream(t, c, stockSync, alignedSync)
	require.Eventually(t, func() bool { return redials.Load() == 1 }, time.Second, 5*time.Millisecond,
		"a stock first response of a new stream must redial once")
	_, ok := c.alignedHeartbeat()
	assert.True(t, ok, "a later explicit config on the stream still applies")

	c.setAlignedAnswer(nil)
	receiveStream(t, c, alignedSync)
	assert.True(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL), "an aligned first response must clear the mark")
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), redials.Load(), "an aligned stream must not redial")
}
