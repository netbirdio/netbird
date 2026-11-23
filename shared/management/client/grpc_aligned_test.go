package client

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/wsproxy"
)

func withAlignedRequest(t *testing.T, period time.Duration, ok bool) {
	t.Helper()
	prev := alignedRequest
	alignedRequest = func() (time.Duration, bool) { return period, ok }
	t.Cleanup(func() { alignedRequest = prev })
}

func lazyMgmtConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

type fakeSyncStream struct {
	proto.ManagementService_SyncClient
	msgs []*proto.EncryptedMessage
	idx  int
}

func (s *fakeSyncStream) Recv() (*proto.EncryptedMessage, error) {
	if s.idx >= len(s.msgs) {
		return nil, io.EOF
	}
	m := s.msgs[s.idx]
	s.idx++
	return m, nil
}

type fakeMgmtClient struct {
	proto.ManagementServiceClient
	stream proto.ManagementService_SyncClient
	gotReq *proto.EncryptedMessage
}

func (f *fakeMgmtClient) Sync(_ context.Context, req *proto.EncryptedMessage, _ ...grpc.CallOption) (proto.ManagementService_SyncClient, error) {
	f.gotReq = req
	return f.stream, nil
}

func encryptedResp(t *testing.T, serverKey, clientKey wgtypes.Key, resp *proto.SyncResponse) *proto.EncryptedMessage {
	t.Helper()
	body, err := encryption.EncryptMessage(serverKey.PublicKey(), clientKey, resp)
	require.NoError(t, err)
	return &proto.EncryptedMessage{WgPubKey: serverKey.PublicKey().String(), Body: body}
}

func newAlignedTestClient(t *testing.T, stream proto.ManagementService_SyncClient) (*GrpcClient, wgtypes.Key, wgtypes.Key) {
	t.Helper()
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: clientKey, ctx: context.Background(), serverURL: "aligned-test.example:443"}
	conn := lazyMgmtConn(t)
	c.conn.Swap(conn, &fakeMgmtClient{stream: stream}, 0)
	return c, clientKey, serverKey
}

func TestPeerCapabilitiesAlignedOnlyWhenAsking(t *testing.T) {
	withAlignedRequest(t, 0, false)
	assert.NotContains(t, peerCapabilities(system.Info{}), proto.PeerCapability_PeerCapabilityAlignedHeartbeat)

	withAlignedRequest(t, alignedhb.DefaultPeriod, true)
	assert.Contains(t, peerCapabilities(system.Info{}), proto.PeerCapability_PeerCapabilityAlignedHeartbeat,
		"a mobile client sends the capability")
}

func TestSyncRequestCarriesPeriod(t *testing.T) {
	withAlignedRequest(t, alignedhb.DefaultPeriod, true)
	stream := &fakeSyncStream{}
	c, clientKey, serverKey := newAlignedTestClient(t, stream)
	fake := c.conn.Client().(*fakeMgmtClient)

	got, err := c.connectToSyncStream(context.Background(), serverKey.PublicKey(), &system.Info{})
	require.NoError(t, err)
	assert.Same(t, stream, got)

	req := &proto.SyncRequest{}
	require.NoError(t, encryption.DecryptMessage(clientKey.PublicKey(), serverKey, fake.gotReq.Body, req))
	assert.Equal(t, uint32(60), req.GetAlignedHeartbeat().GetPeriodSeconds())
}

func TestReceiveAlignedAnswerAndHeartbeat(t *testing.T) {
	withAlignedRequest(t, alignedhb.DefaultPeriod, true)
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	addr := "aligned-answer.example:443"
	nbgrpc.MarkStock(wsproxy.ManagementComponent, addr)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.ManagementComponent, addr) })

	w := hbwatch.New(wallClock{}, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	w.Register(hbwatch.Management, hbwatch.Registration{Addr: addr})

	// A response without a peer config decides nothing: the answer is read
	// from the first response that carries one.
	noPeerConfig := &proto.SyncResponse{Checks: []*proto.Checks{}}
	first := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{
		AlignedHeartbeat: &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 10},
	}}
	heartbeat := &proto.SyncResponse{Heartbeat: &proto.Heartbeat{}}
	update := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{Address: "100.64.0.1/24"}}
	stream := &fakeSyncStream{msgs: []*proto.EncryptedMessage{
		encryptedResp(t, serverKey, clientKey, noPeerConfig),
		encryptedResp(t, serverKey, clientKey, first),
		encryptedResp(t, serverKey, clientKey, heartbeat),
		encryptedResp(t, serverKey, clientKey, update),
	}}

	c := &GrpcClient{key: clientKey, ctx: context.Background(), serverURL: addr}
	c.conn.Swap(lazyMgmtConn(t), &fakeMgmtClient{stream: stream}, 0)

	var handled []*proto.SyncResponse
	err = c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(msg *proto.SyncResponse) error {
		handled = append(handled, msg)
		return nil
	})
	assert.ErrorIs(t, err, io.EOF)
	assert.Len(t, handled, 3, "the heartbeat never reaches the handler")
	assert.Equal(t, alignedhb.MinPeriod, c.getAlignedPeriod(), "the answer period is clamped")
	assert.True(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, addr), "the aligned answer cleared the stock mark")

	snap := w.Snapshot()
	require.Len(t, snap.Streams, 1)
	assert.True(t, snap.Streams[0].Aligned, "the heartbeat reaches hbwatch")
	assert.Equal(t, alignedhb.MinPeriod, snap.Streams[0].Period)
}

type wallClock struct{}

func (wallClock) Now() time.Time                      { return time.Now() }
func (wallClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }

func TestReceiveStockAnswerMarksAndRedials(t *testing.T) {
	withAlignedRequest(t, alignedhb.DefaultPeriod, true)
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	addr := "stock-answer.example:443"
	nbgrpc.ClearStock(wsproxy.ManagementComponent, addr)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.ManagementComponent, addr) })

	first := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{Address: "100.64.0.1/24"}}
	stream := &fakeSyncStream{msgs: []*proto.EncryptedMessage{
		encryptedResp(t, serverKey, clientKey, first),
	}}

	c := &GrpcClient{key: clientKey, ctx: context.Background(), serverURL: addr}
	stockConn := lazyMgmtConn(t)
	c.conn.Swap(lazyMgmtConn(t), &fakeMgmtClient{stream: stream}, alignedhb.ReceiveTimeout(alignedhb.DefaultPeriod))
	c.dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) {
		return stockConn, 30 * time.Second, nil
	}

	err = c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(*proto.SyncResponse) error { return nil })
	assert.ErrorIs(t, err, io.EOF)
	require.Eventually(t, func() bool { return c.conn.Conn() == stockConn }, 5*time.Second, 10*time.Millisecond,
		"a stock answer redials with the stock keepalive")
	assert.Zero(t, c.getAlignedPeriod(), "the stream runs stock")
}
