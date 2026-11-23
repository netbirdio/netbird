package client

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/util/wsproxy"
)

func withSignalAlignedRequest(c *GrpcClient, period time.Duration, ok bool) {
	c.alignedRequest = func() (time.Duration, bool) { return period, ok }
}

func lazySignalConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

type fakeSignalStream struct {
	proto.SignalExchange_ConnectStreamClient
	header metadata.MD
	msgs   []*proto.EncryptedMessage
	idx    int
}

func (s *fakeSignalStream) Header() (metadata.MD, error) { return s.header, nil }

func (s *fakeSignalStream) Recv() (*proto.EncryptedMessage, error) {
	if s.idx >= len(s.msgs) {
		return nil, io.EOF
	}
	m := s.msgs[s.idx]
	s.idx++
	return m, nil
}

type fakeSignalClient struct {
	proto.SignalExchangeClient
	stream *fakeSignalStream
	md     metadata.MD
}

func (f *fakeSignalClient) ConnectStream(ctx context.Context, _ ...grpc.CallOption) (proto.SignalExchange_ConnectStreamClient, error) {
	f.md, _ = metadata.FromOutgoingContext(ctx)
	return f.stream, nil
}

func (f *fakeSignalClient) Send(context.Context, *proto.EncryptedMessage, ...grpc.CallOption) (*proto.EncryptedMessage, error) {
	return &proto.EncryptedMessage{}, nil
}

func newSignalTestClient(t *testing.T, addr string) *GrpcClient {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return &GrpcClient{
		key:                       key,
		sharedKeys:                encryption.NewSharedKeyCache(key),
		ctx:                       context.Background(),
		serverURL:                 addr,
		registrationTimeout:       defaultRegistrationTimeout,
		registrationProbeInterval: time.Hour,
	}
}

func TestConnectSendsPeriodAndReadsAlignedAnswer(t *testing.T) {
	addr := "signal-aligned.example:443"
	nbgrpc.ClearStock(wsproxy.SignalComponent, addr)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.SignalComponent, addr) })

	stream := &fakeSignalStream{header: metadata.Pairs(
		proto.HeaderRegistered, "1",
		alignedhb.MetadataKey, "period=10;phase=1",
	)}
	fake := &fakeSignalClient{stream: stream}
	c := newSignalTestClient(t, addr)
	withSignalAlignedRequest(c, alignedhb.DefaultPeriod, true)
	c.conn.Swap(lazySignalConn(t), fake, 0)

	got, err := c.connect(context.Background(), func() {}, c.key.PublicKey().String())
	require.NoError(t, err)
	assert.Same(t, stream, got)
	assert.Equal(t, []string{"period=60"}, fake.md.Get(alignedhb.MetadataKey), "the request carries the period only")
	assert.Equal(t, alignedhb.MinPeriod, c.getAlignedPeriod(), "the answer period is clamped, later fields ignored")
	assert.Equal(t, alignedhb.ReceiveTimeout(alignedhb.MinPeriod), c.inactivityThreshold(),
		"the watchdog waits for the aligned heartbeat")
}

func TestConnectStockAnswerMarksAndRedials(t *testing.T) {
	addr := "signal-stock.example:443"
	nbgrpc.ClearStock(wsproxy.SignalComponent, addr)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.SignalComponent, addr) })

	stream := &fakeSignalStream{header: metadata.Pairs(proto.HeaderRegistered, "1")}
	fake := &fakeSignalClient{stream: stream}
	c := newSignalTestClient(t, addr)
	withSignalAlignedRequest(c, alignedhb.DefaultPeriod, true)
	stockConn := lazySignalConn(t)
	c.conn.Swap(lazySignalConn(t), fake, alignedhb.ReceiveTimeout(alignedhb.DefaultPeriod))
	c.dial = func(context.Context) (*grpc.ClientConn, time.Duration, error) {
		return stockConn, 30 * time.Second, nil
	}

	_, err := c.connect(context.Background(), func() {}, c.key.PublicKey().String())
	require.NoError(t, err)
	assert.Zero(t, c.getAlignedPeriod(), "no answer, the stream runs stock")
	require.Eventually(t, func() bool { return c.conn.Conn() == stockConn }, 5*time.Second, 10*time.Millisecond,
		"a stock answer redials with the stock keepalive")
	assert.Equal(t, receiveInactivityThreshold, c.inactivityThreshold(), "the watchdog stays stock")
}

func TestConnectBadAnswerIsStock(t *testing.T) {
	c := newSignalTestClient(t, "signal-bad.example:443")
	withSignalAlignedRequest(c, alignedhb.DefaultPeriod, true)
	c.conn.Swap(lazySignalConn(t), &fakeSignalClient{}, 30*time.Second)

	c.applyAlignedAnswer(metadata.Pairs(alignedhb.MetadataKey, "phase=1"), c.key.PublicKey().String())
	assert.Zero(t, c.getAlignedPeriod(), "a value without a period is a stock answer")
	assert.Equal(t, receiveInactivityThreshold, c.inactivityThreshold())
}

// TestReceiveServerHeartbeatCheck: a heartbeat with an empty key and body is
// accepted, any other message carrying the field is dropped, and neither
// reaches the decryption worker (nil here, so reaching it would panic).
func TestReceiveServerHeartbeatCheck(t *testing.T) {
	w := hbwatch.New(newTestClock(), time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	w.Register(hbwatch.Signal, hbwatch.Registration{})
	signalAligned := func() bool {
		snap := w.Snapshot()
		return len(snap.Streams) == 1 && snap.Streams[0].Aligned
	}

	c := newSignalTestClient(t, "signal-heartbeat.example:443")
	c.setAlignedPeriod(time.Minute)
	forged := &fakeSignalStream{msgs: []*proto.EncryptedMessage{
		{Key: "forged", ServerHeartbeat: &proto.ServerHeartbeat{}},
		{Body: []byte("forged"), ServerHeartbeat: &proto.ServerHeartbeat{}},
	}}
	assert.ErrorIs(t, c.receive(forged), io.EOF)
	assert.Equal(t, len(forged.msgs), forged.idx, "every forged heartbeat was consumed")
	assert.False(t, signalAligned(), "a heartbeat with a sender key or a body never counts")

	valid := &fakeSignalStream{msgs: []*proto.EncryptedMessage{
		{RemoteKey: "peer", ServerHeartbeat: &proto.ServerHeartbeat{}},
	}}
	assert.ErrorIs(t, c.receive(valid), io.EOF)
	assert.True(t, signalAligned(), "a heartbeat with an empty key and body counts")
}

// TestReceiveWakeCheckReconnectsAlignedStreamWithoutHeartbeat: a stream
// that got an aligned answer and then no heartbeat at all is reconnected by
// the wake check once it is silent past the receive timeout.
func TestReceiveWakeCheckReconnectsAlignedStreamWithoutHeartbeat(t *testing.T) {
	clk := newTestClock()
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))

	stream := &blockingSignalStream{header: metadata.Pairs(
		proto.HeaderRegistered, "1",
		alignedhb.MetadataKey, "period=60",
	)}
	c := newSignalTestClient(t, "signal-wake.example:443")
	withSignalAlignedRequest(c, alignedhb.DefaultPeriod, true)
	c.conn.Swap(lazySignalConn(t), &blockingSignalClient{stream: stream}, alignedhb.ReceiveTimeout(alignedhb.DefaultPeriod))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Receive(ctx, func(*proto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = c.Close()
	})

	require.Eventually(t, func() bool {
		snap := w.Snapshot()
		return len(snap.Streams) == 1 && snap.Streams[0].Period == time.Minute
	}, 5*time.Second, 10*time.Millisecond, "the stream registers with its answered period")
	require.Equal(t, 1, stream.opened())

	clk.Advance(alignedhb.ReceiveTimeout(time.Minute) + time.Second)
	w.CheckNow()
	clk.Advance(hbwatch.Grace)
	assert.Eventually(t, func() bool { return stream.opened() == 2 }, 5*time.Second, 10*time.Millisecond,
		"the wake check reconnects the silent aligned stream")
}

// blockingSignalStream answers the registration header and then blocks in
// Recv until its stream context ends, like a stream that gets no message.
type blockingSignalStream struct {
	proto.SignalExchange_ConnectStreamClient
	header metadata.MD

	mu    sync.Mutex
	ctx   context.Context
	opens int
}

func (s *blockingSignalStream) open(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = ctx
	s.opens++
}

func (s *blockingSignalStream) opened() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens
}

func (s *blockingSignalStream) Header() (metadata.MD, error) { return s.header, nil }

func (s *blockingSignalStream) Recv() (*proto.EncryptedMessage, error) {
	s.mu.Lock()
	ctx := s.ctx
	s.mu.Unlock()
	<-ctx.Done()
	return nil, status.Error(codes.Canceled, ctx.Err().Error())
}

type blockingSignalClient struct {
	proto.SignalExchangeClient
	stream *blockingSignalStream
}

func (f *blockingSignalClient) ConnectStream(ctx context.Context, _ ...grpc.CallOption) (proto.SignalExchange_ConnectStreamClient, error) {
	f.stream.open(ctx)
	return f.stream, nil
}

func (f *blockingSignalClient) Send(context.Context, *proto.EncryptedMessage, ...grpc.CallOption) (*proto.EncryptedMessage, error) {
	return &proto.EncryptedMessage{}, nil
}

// testClock is a wall clock that moves only with Advance.
type testClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []testTimer
}

type testTimer struct {
	due time.Time
	f   func()
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) AfterFunc(d time.Duration, f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timers = append(c.timers, testTimer{due: c.now.Add(d), f: f})
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	var keep []testTimer
	for _, t := range c.timers {
		if t.due.After(c.now) {
			keep = append(keep, t)
		} else {
			due = append(due, t.f)
		}
	}
	c.timers = keep
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}
