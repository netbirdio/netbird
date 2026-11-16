package client

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	gstatus "google.golang.org/grpc/status"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// downManagement answers every server key request like a proxy in front of a
// stopped server, and counts the requests: one per stream attempt.
type downManagement struct {
	proto.ManagementServiceClient
	attempts atomic.Int32
}

func (f *downManagement) GetServerKey(context.Context, *proto.Empty, ...grpc.CallOption) (*proto.ServerKeyResponse, error) {
	f.attempts.Add(1)
	return nil, gstatus.Error(codes.Unavailable, "502 Bad Gateway")
}

// setStreamBackoff makes the stream retry loops wait d between attempts. With
// d far beyond the test run no timer ends a wait: only a wake can.
func setStreamBackoff(t *testing.T, d time.Duration) {
	t.Helper()
	old := streamBackoff
	streamBackoff = func(ctx context.Context) backoff.BackOff {
		return backoff.WithContext(backoff.NewConstantBackOff(d), ctx)
	}
	t.Cleanup(func() { streamBackoff = old })
}

// startStreams runs the Sync and Job retry loops against a Management that is
// down, until the test ends.
func startStreams(t *testing.T) *downManagement {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	c := &GrpcClient{key: key, ctx: ctx}
	fake := &downManagement{}
	c.conn.Swap(lazyConn(t), fake, 30*time.Second)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = c.Sync(ctx, func(context.Context) *system.Info { return &system.Info{} },
			func(*proto.SyncResponse) error { return nil })
	}()
	go func() {
		defer wg.Done()
		_ = c.Job(ctx, func(*proto.JobRequest) *proto.JobResponse { return &proto.JobResponse{} })
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return fake
}

// expectAttempts waits for want attempts in total, then checks that no more
// come without another wake.
func expectAttempts(t *testing.T, fake *downManagement, want int32, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return fake.attempts.Load() >= want }, 2*time.Second, 5*time.Millisecond, msg)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, want, fake.attempts.Load(), "%s: no attempt between wakes", msg)
}

// Management drops while Signal keeps ticking on a locked phone. The
// retries wait on 10 s timers that the sleeping phone never runs out. Every
// burst after the fast window gets exactly one attempt per stream, and nothing
// goes between the bursts.
func TestManagementRetryAtEveryBurstWhileAsleep(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	setStreamBackoff(t, 10*time.Second)

	w.Register(hbwatch.Signal, hbwatch.Registration{Kind: hbwatch.ActionReconnect, Stale: func() {}})
	hb := hbwatch.Heartbeat{Period: time.Minute}
	w.Seen(hbwatch.Signal, hb)
	w.SetDeviceAsleep(true)

	fake := startStreams(t)
	expectAttempts(t, fake, 2, "the drop: one attempt per stream")

	// A device wake inside the 10 s backoff ends no wait.
	clk.jump(5 * time.Second)
	w.SetDeviceAsleep(false)
	w.SetDeviceAsleep(true)
	expectAttempts(t, fake, 2, "a wake before the wall deadline")

	want := int32(2)
	for burst := 1; burst <= 4; burst++ {
		clk.jump(time.Minute)
		w.Seen(hbwatch.Signal, hb)
		want += 2
		expectAttempts(t, fake, want, "burst wake")
	}
}

// Every stream is down, so nothing ticks and the gate does not hold. The
// phone sleeps 3 min; its device wake starts every overdue retry.
func TestManagementRetryAtDeviceWakeAllDown(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	setStreamBackoff(t, 10*time.Second)
	w.SetDeviceAsleep(true)

	fake := startStreams(t)
	expectAttempts(t, fake, 2, "the drop: one attempt per stream")

	clk.jump(3 * time.Minute)
	w.SetDeviceAsleep(false)
	expectAttempts(t, fake, 4, "the device wake starts both overdue retries")
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// The gRPC channel's own reconnect backoff runs on a timer the sleeping phone
// does not run out. A wake past its wall deadline ends it, and the redial goes
// through the dial hold.
func TestChannelBackoffEndsAtWake(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key, ctx: context.Background()}
	c.downSince.Store(clk.Now().UnixNano())

	var dials atomic.Int32
	hold := func(ctx context.Context) error {
		if err := c.waitDial(ctx); err != nil {
			return err
		}
		dials.Add(1)
		return nil
	}
	// gRPC's own backoff is an hour here, so only a reset redials.
	conn, err := grpc.NewClient(closedAddr(t),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           grpcbackoff.Config{BaseDelay: time.Hour, Multiplier: 1, MaxDelay: time.Hour},
			MinConnectTimeout: time.Second,
		}),
		nbgrpc.WithDialHooks(nil, nil, hold))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	swapConn(c, conn, 30*time.Second)
	t.Cleanup(w.OnWake(c.onWake))
	conn.Connect()

	require.Eventually(t, func() bool {
		return dials.Load() == 1 && conn.GetState() == connectivity.TransientFailure
	}, 5*time.Second, 5*time.Millisecond, "the first dial fails")
	assert.Equal(t, int32(1), c.dialsDown.Load(), "the hold counts the dial")

	// After many failed dials the channel waits up to 144 s: a wake now is early.
	c.dialsDown.Store(20)
	w.SetDeviceAsleep(false)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, int32(1), dials.Load(), "a wake before the wall deadline must not redial")

	clk.jump(3 * time.Minute)
	w.SetDeviceAsleep(false)
	require.Eventually(t, func() bool { return dials.Load() == 2 }, 5*time.Second, 5*time.Millisecond,
		"the wake past the wall deadline redials")

	// Streams up: no reset, whatever the clock.
	c.downSince.Store(0)
	require.Eventually(t, func() bool { return conn.GetState() == connectivity.TransientFailure }, 5*time.Second, 5*time.Millisecond)
	clk.jump(time.Hour)
	w.SetDeviceAsleep(false)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, int32(2), dials.Load(), "no redial while the streams are up")
}

func TestChannelBackoffBound(t *testing.T) {
	assert.Equal(t, 1200*time.Millisecond, channelBackoffBound(1), "first failure: base delay plus jitter")
	assert.Equal(t, 1920*time.Millisecond, channelBackoffBound(2))
	assert.Equal(t, 144*time.Second, channelBackoffBound(50), "capped at the max delay plus jitter")
}
