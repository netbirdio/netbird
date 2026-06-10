package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// blockingMgmtClient implements roundtrip's managementClient interface.
// CreateProxyPeer parks until release is closed, signalling entry on entered.
// This reproduces the confirmed real-world stall: createClientEntry calls
// CreateProxyPeer synchronously while holding clientsMux, and the proxy's
// receive loop calls that path synchronously inside processMappings.
type blockingMgmtClient struct {
	entered chan struct{}
	once    sync.Once
}

func (b *blockingMgmtClient) CreateProxyPeer(ctx context.Context, _ *proto.CreateProxyPeerRequest, _ ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	b.once.Do(func() { close(b.entered) })
	// Park until the caller's context is cancelled. In production this ctx is
	// the gRPC mapping-stream context with no per-call timeout, so a slow or
	// unresponsive CreateProxyPeer parks the receive loop here indefinitely.
	<-ctx.Done()
	return nil, ctx.Err()
}

// gatedMappingStream is a mock GetMappingUpdate client stream that hands out a
// pre-seeded list of messages, then records how many times Recv advanced. It
// lets the test observe whether the single-threaded receive loop ever gets
// past the first (blocking) batch to pull the second message.
type gatedMappingStream struct {
	grpc.ClientStream
	messages []*proto.GetMappingUpdateResponse
	idx      int32
}

func (g *gatedMappingStream) Recv() (*proto.GetMappingUpdateResponse, error) {
	i := int(atomic.LoadInt32(&g.idx))
	if i >= len(g.messages) {
		// Block instead of returning EOF so the loop doesn't exit; we only
		// care whether the loop ever reaches this second Recv at all.
		select {}
	}
	msg := g.messages[i]
	atomic.AddInt32(&g.idx, 1)
	return msg, nil
}

func (g *gatedMappingStream) deliveredCount() int32 { return atomic.LoadInt32(&g.idx) }

func (g *gatedMappingStream) Header() (metadata.MD, error) { return nil, nil } //nolint:nilnil
func (g *gatedMappingStream) Trailer() metadata.MD         { return nil }
func (g *gatedMappingStream) CloseSend() error             { return nil }
func (g *gatedMappingStream) Context() context.Context     { return context.Background() }
func (g *gatedMappingStream) SendMsg(any) error            { return nil }
func (g *gatedMappingStream) RecvMsg(any) error            { return nil }

// noopNotifier satisfies roundtrip's statusNotifier interface.
type noopNotifier struct{}

func (noopNotifier) NotifyStatus(context.Context, types.AccountID, types.ServiceID, bool) error {
	return nil
}

// noopProxyClient is a proto.ProxyServiceClient that no-ops the one method the
// teardown unwind reaches (SendStatusUpdate, via notifyError when the parked
// AddPeer is cancelled). The embedded nil interface satisfies the rest at
// compile time; none of those methods are called by this test.
type noopProxyClient struct {
	proto.ProxyServiceClient
}

func (noopProxyClient) SendStatusUpdate(context.Context, *proto.SendStatusUpdateRequest, ...grpc.CallOption) (*proto.SendStatusUpdateResponse, error) {
	return &proto.SendStatusUpdateResponse{}, nil
}

// TestMappingStream_StallsWhenApplyBlocks proves the deadlock: the proxy's
// mapping receive loop processes batches strictly serially, so when applying
// one batch blocks (here: createClientEntry parked on a synchronous
// CreateProxyPeer call, exactly as observed in production), the loop never
// advances to Recv the next batch. Management can keep sending updates onto
// the stream with no error and no channel overflow, yet the proxy applies
// nothing further — it is stuck.
func TestMappingStream_StallsWhenApplyBlocks(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.PanicLevel)

	mgmt := &blockingMgmtClient{
		entered: make(chan struct{}),
	}

	nb := roundtrip.NewNetBird(
		context.Background(),
		"proxy-test",
		"proxy.example.com",
		roundtrip.ClientConfig{},
		logger,
		noopNotifier{},
		mgmt,
	)

	s := &Server{
		Logger:       logger,
		netbird:      nb,
		mgmtClient:   noopProxyClient{},
		routerReady:  closedChan(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
	}

	// First batch: a CREATED mapping for a brand-new account. addMapping ->
	// netbird.AddPeer -> createClientEntry -> CreateProxyPeer, which blocks.
	// Empty Path keeps setupHTTPMapping a no-op (it returns early), so the
	// ONLY blocking point is the synchronous CreateProxyPeer in AddPeer —
	// no routers/auth need wiring. The second batch exists only to detect
	// whether the loop ever advances past the blocked first batch.
	stream := &gatedMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{
				Mapping: []*proto.ProxyMapping{
					{
						Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
						Id:        "svc-1",
						AccountId: "acct-1",
						AuthToken: "token-1",
					},
				},
			},
			{
				Mapping: []*proto.ProxyMapping{
					{
						Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
						Id:        "svc-2",
						AccountId: "acct-2",
						AuthToken: "token-2",
					},
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Unblock the parked apply on teardown via ctx (CreateProxyPeer returns
	// ctx.Err()), so the wedged loop goroutine unwinds before embed.New —
	// avoiding any dependency on collaborators this test deliberately leaves
	// nil. The deadlock is fully proven before this fires.
	t.Cleanup(cancel)

	loopDone := make(chan struct{})
	syncDone := false
	go func() {
		defer close(loopDone)
		_ = s.handleMappingStream(ctx, stream, &syncDone, time.Time{})
	}()

	// The loop must reach the blocking apply for the first batch.
	select {
	case <-mgmt.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop never reached CreateProxyPeer for the first batch")
	}

	// THE DEADLOCK: while the first batch is parked in CreateProxyPeer, the
	// single-threaded loop cannot advance. The second batch is never pulled,
	// even though it is already available on the stream. Give it ample time.
	// deliveredCount is atomic; syncDone is intentionally not read here because
	// the loop goroutine owns it (reading it from the test would race).
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(1), stream.deliveredCount(),
		"loop must NOT consume the second batch while the first is blocked in apply — proxy is stuck")

	select {
	case <-loopDone:
		t.Fatal("receive loop returned while it should be wedged in apply")
	default:
		// Still wedged, as expected.
	}
}

// TestMappingStream_StallsWhenRemoveBlocks proves the deadlock for the REMOVE
// path observed in production: a mapping remove tears down the account's last
// embedded client via netbird.RemovePeer -> client.Stop -> Engine.Stop, whose
// jobExecutorWG.Wait() is unbounded. Because the receive loop is single-
// threaded, a blocked remove wedges the loop: no further mapping updates of any
// kind (create/modify/remove) are applied, while management keeps sending them
// successfully (no send error, no channel-full). Matches the reported symptom:
// the last log line is a remove that stops a client, then silence.
func TestMappingStream_StallsWhenRemoveBlocks(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.PanicLevel)

	enteredRemove := make(chan struct{})
	blockRemove := make(chan struct{})
	var once sync.Once

	s := &Server{
		Logger:       logger,
		mgmtClient:   noopProxyClient{},
		routerReady:  closedChan(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		// Stand in for netbird.RemovePeer -> client.Stop hanging on
		// Engine.Stop's unbounded jobExecutorWG.Wait(). Only the first remove
		// blocks; later removes return immediately so the recovery assertion
		// can observe the loop advancing.
		removePeer: func(ctx context.Context, _ types.AccountID, _ roundtrip.ServiceKey) error {
			first := false
			once.Do(func() {
				first = true
				close(enteredRemove)
			})
			if !first {
				return nil
			}
			select {
			case <-blockRemove:
			case <-ctx.Done():
			}
			return nil
		},
	}

	// Batch 1 removes a service (blocks in teardown). Batch 2 is a later update
	// that must never be applied while the remove is wedged.
	stream := &gatedMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{
				Mapping: []*proto.ProxyMapping{
					{Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, Id: "svc-1", AccountId: "acct-1"},
				},
			},
			{
				Mapping: []*proto.ProxyMapping{
					{Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, Id: "svc-2", AccountId: "acct-1"},
				},
			},
		},
	}

	loopDone := make(chan struct{})
	syncDone := false
	go func() {
		defer close(loopDone)
		_ = s.handleMappingStream(context.Background(), stream, &syncDone, time.Time{})
	}()

	select {
	case <-enteredRemove:
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop never reached the blocking remove for the first batch")
	}

	// THE DEADLOCK: the loop is parked in the blocked remove and cannot advance.
	// syncDone is owned by the loop goroutine, so it is not read here.
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(1), stream.deliveredCount(),
		"loop must NOT consume the second batch while the first remove is blocked — proxy is stuck")

	select {
	case <-loopDone:
		t.Fatal("receive loop returned while it should be wedged on the remove")
	default:
	}

	// Unblock and confirm the wedge was solely the blocked remove: the loop
	// then advances and consumes the next batch.
	close(blockRemove)
	assert.Eventually(t, func() bool {
		return stream.deliveredCount() >= 2
	}, 2*time.Second, 5*time.Millisecond,
		"once the remove unblocks, the loop must advance and consume the next batch")
}
