package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// jumpClock is a wall clock moved by hand whose timers run at once, so a
// CheckNow is checked without waiting out the grace.
type jumpClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *jumpClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *jumpClock) AfterFunc(_ time.Duration, f func()) { go f() }

func (c *jumpClock) jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// silentSyncStream delivers nothing, like a Sync stream whose server died
// behind a proxy, and ends only when its context is cancelled.
type silentSyncStream struct {
	grpc.ClientStream
	ctx context.Context
}

func (s *silentSyncStream) Recv() (*proto.EncryptedMessage, error) {
	<-s.ctx.Done()
	return nil, gstatus.Error(codes.Canceled, s.ctx.Err().Error())
}

type silentSyncClient struct {
	proto.ManagementServiceClient
	opened chan struct{}
}

func (f *silentSyncClient) Sync(ctx context.Context, _ *proto.EncryptedMessage, _ ...grpc.CallOption) (proto.ManagementService_SyncClient, error) {
	close(f.opened)
	return &silentSyncStream{ctx: ctx}, nil
}

// A stale Sync stream is cancelled, and the cancel must come back as a
// retryable error, not as the nil that means shutdown.
func TestStaleSyncStreamCancelsAndRetries(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	restore := hbwatch.SetDefault(hbwatch.New(clk, 30*time.Second))
	t.Cleanup(restore)

	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	fake := &silentSyncClient{opened: make(chan struct{})}
	c := &GrpcClient{key: clientKey, realClient: fake}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- c.handleSyncStream(ctx, serverKey.PublicKey(),
			func(context.Context) *system.Info { return &system.Info{} },
			func(*proto.SyncResponse) error { return nil },
			backoff.NewConstantBackOff(time.Second))
	}()
	<-fake.opened

	// Registration happens right after the stream opens; keep jumping past
	// period + tolerance and waking until the stale action runs. A Signal
	// test heartbeat marks a test mode, so the stale check acts.
	var got error
	require.Eventually(t, func() bool {
		clk.jump(60 * time.Second)
		hbwatch.Seen(hbwatch.Signal)
		hbwatch.CheckNow()
		select {
		case got = <-done:
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 3*time.Second, time.Millisecond, "stale Sync stream must be cancelled")

	require.Error(t, got, "a stale-check cancel must be retried, not treated as shutdown")
	var permanent *backoff.PermanentError
	assert.False(t, errors.As(got, &permanent), "the error must be retryable")
	assert.Error(t, c.syncStreamError(), "the Sync stream must be marked disconnected")
	assert.NoError(t, ctx.Err(), "the parent context is untouched")
}
