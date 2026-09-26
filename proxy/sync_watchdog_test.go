package proxy

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// A large snapshot is applied one mapping at a time inside the SyncMappings
// receive loop, and the first mapping of every new account pays a synchronous
// CreateProxyPeer round trip. When one batch takes longer than
// MappingBatchWatchdog the proxy drops the stream, reconnects and starts the
// snapshot again. Accounts created before the trip are reused, so every pass
// ratchets forward, but the stream never acks a batch, initial sync never
// completes, and management sees a proxy that connects and disconnects.

const (
	watchdogSnapshotAccounts = 600
	watchdogCreatePeerDelay  = 10 * time.Millisecond
)

// fakeSyncStream hands out a snapshot as [batch, {InitialSyncComplete}] and
// counts every ack. After the last message Recv blocks until ctx is done, like
// an idle live stream.
type fakeSyncStream struct {
	grpc.ClientStream
	ctx      context.Context
	messages []*proto.SyncMappingsResponse
	idx      int
	acks     *atomic.Int32
}

func (f *fakeSyncStream) Recv() (*proto.SyncMappingsResponse, error) {
	if f.idx >= len(f.messages) {
		<-f.ctx.Done()
		return nil, io.EOF
	}
	m := f.messages[f.idx]
	f.idx++
	return m, nil
}

func (f *fakeSyncStream) Send(req *proto.SyncMappingsRequest) error {
	if req.GetAck() != nil {
		f.acks.Add(1)
	}
	return nil
}

func (f *fakeSyncStream) Header() (metadata.MD, error) { return nil, nil } //nolint:nilnil
func (f *fakeSyncStream) Trailer() metadata.MD         { return nil }
func (f *fakeSyncStream) CloseSend() error             { return nil }
func (f *fakeSyncStream) Context() context.Context     { return f.ctx }
func (f *fakeSyncStream) SendMsg(any) error            { return nil }
func (f *fakeSyncStream) RecvMsg(any) error            { return nil }

// snapshotMgmtClient is the management the mapping worker dials. Every
// SyncMappings call is one (re)connect that replays the same snapshot, and
// CreateProxyPeer is slowed down per new account like a loaded management.
// CreateProxyPeer is made to fail after the delay so the test stays offline:
// a successful creation would build an embedded client whose management dial
// re-initialises the process-global gRPC logger from createClientEntry, which
// the race detector flags against the previous test's dial goroutines. The
// batch time budget is the same either way; what the failure hides is that in
// production accounts created before a watchdog trip survive the reconnect and
// each pass ratchets forward.
type snapshotMgmtClient struct {
	latencyMockClient
	snapshot []*proto.ProxyMapping
	connects atomic.Int32
	acks     atomic.Int32
}

func (c *snapshotMgmtClient) SyncMappings(ctx context.Context, _ ...grpc.CallOption) (proto.ProxyService_SyncMappingsClient, error) {
	c.connects.Add(1)
	return &fakeSyncStream{
		ctx: ctx,
		messages: []*proto.SyncMappingsResponse{
			{Mapping: c.snapshot},
			{InitialSyncComplete: true},
		},
		acks: &c.acks,
	}, nil
}

// noStartupClients makes the startup probe depend only on management
// connectivity and initial-sync completion, not on embedded clients that this
// offline test never starts.
type noStartupClients struct{}

func (noStartupClients) ListClientsForStartup() map[types.AccountID]*embed.Client { return nil }

// snapshotOfNewAccounts builds one batch in which every mapping belongs to a
// different account, so each one costs a CreateProxyPeer. An empty Path keeps
// setupHTTPMapping a no-op.
func snapshotOfNewAccounts(n int) []*proto.ProxyMapping {
	out := make([]*proto.ProxyMapping, n)
	for i := range out {
		out[i] = &proto.ProxyMapping{
			Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
			Id:        fmt.Sprintf("svc-%d", i),
			AccountId: fmt.Sprintf("acct-%d", i),
			AuthToken: "tok",
		}
	}
	return out
}

// runMappingWorker starts the management mapping worker against mgmt with the
// given batch watchdog and stops it on cleanup. Assertions on the health
// checker must run while the worker is alive.
func runMappingWorker(t *testing.T, mgmt *snapshotMgmtClient, watchdog time.Duration) (*Server, *health.Checker) {
	t.Helper()
	s := newServerWithMgmtClient(t, mgmt)
	checker := health.NewChecker(s.Logger, noStartupClients{})
	s.healthChecker = checker
	s.routerReady = closedChan()
	s.MappingBatchWatchdog = watchdog

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.newManagementMappingWorker(ctx, mgmt)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return s, checker
}

// TestRepro_SyncSnapshot_WatchdogReconnectLoop: 600 new accounts at 10 ms per
// CreateProxyPeer need 6 s per batch, the watchdog fires after 500 ms. Within
// the observation window the worker reconnects repeatedly, no batch is ever
// acked and the startup probe stays red.
func TestRepro_SyncSnapshot_WatchdogReconnectLoop(t *testing.T) {
	mgmt := &snapshotMgmtClient{
		latencyMockClient: latencyMockClient{createPeerDelay: watchdogCreatePeerDelay, createPeerFail: true},
		snapshot:          snapshotOfNewAccounts(watchdogSnapshotAccounts),
	}
	_, checker := runMappingWorker(t, mgmt, 500*time.Millisecond)

	time.Sleep(3 * time.Second)

	connects := mgmt.connects.Load()
	acks := mgmt.acks.Load()
	t.Logf("after 3s: connects=%d acks=%d startup probe=%v",
		connects, acks, checker.StartupProbe(context.Background()))

	assert.GreaterOrEqual(t, connects, int32(2), "the worker must reconnect after the watchdog fires")
	assert.Equal(t, int32(0), acks, "no batch may be acked while every pass trips the watchdog")
	assert.False(t, checker.StartupProbe(context.Background()), "initial sync must not complete")
}

// TestSyncSnapshot_WatchdogAboveBatchCost is the control: with the watchdog
// above the cost of one batch the same snapshot is acked on the first
// connection and the startup probe turns green.
func TestSyncSnapshot_WatchdogAboveBatchCost(t *testing.T) {
	mgmt := &snapshotMgmtClient{
		latencyMockClient: latencyMockClient{createPeerDelay: watchdogCreatePeerDelay, createPeerFail: true},
		snapshot:          snapshotOfNewAccounts(watchdogSnapshotAccounts),
	}
	_, checker := runMappingWorker(t, mgmt, 60*time.Second)

	require.Eventually(t, func() bool { return checker.StartupProbe(context.Background()) },
		30*time.Second, 50*time.Millisecond, "initial sync must complete")
	t.Logf("connects=%d acks=%d", mgmt.connects.Load(), mgmt.acks.Load())

	assert.Equal(t, int32(1), mgmt.connects.Load(), "a single connection must suffice")
	assert.Equal(t, int32(2), mgmt.acks.Load(), "both snapshot messages must be acked")
}
