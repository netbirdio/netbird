package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

// downSignal fails every stream open like a proxy in front of a stopped
// server, and counts the opens.
type downSignal struct {
	proto.SignalExchangeClient
	attempts atomic.Int32
}

func (f *downSignal) ConnectStream(context.Context, ...grpc.CallOption) (proto.SignalExchange_ConnectStreamClient, error) {
	f.attempts.Add(1)
	return nil, gstatus.Error(codes.Unavailable, "502 Bad Gateway")
}

// The phone slept through the receive loop's backoff: the wall clock moved,
// the timer did not. The device wake reopens the stream at once.
func TestSignalReceiveRetryAtWake(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	old := receiveBackoff
	receiveBackoff = func(ctx context.Context) backoff.BackOff {
		return backoff.WithContext(backoff.NewConstantBackOff(10*time.Second), ctx)
	}
	t.Cleanup(func() { receiveBackoff = old })
	w.SetDeviceAsleep(true)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key, ctx: context.Background()}
	fake := &downSignal{}
	c.conn.Swap(lazySignalConn(t), fake, 30*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Receive(ctx, func(*proto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	require.Eventually(t, func() bool { return fake.attempts.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	w.SetDeviceAsleep(false)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(1), fake.attempts.Load(), "a wake before the wall deadline must not retry")

	w.SetDeviceAsleep(true)
	clk.jump(3 * time.Minute)
	w.SetDeviceAsleep(false)
	require.Eventually(t, func() bool { return fake.attempts.Load() == 2 }, time.Second, 5*time.Millisecond,
		"the device wake past the wall deadline reopens the stream")
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(2), fake.attempts.Load(), "one attempt per wake")
}

// All streams are down, so no burst will come. The phone slept during the
// receive loop's backoff and woke before its wall deadline: that wake is the
// only chance to reconnect, so the stream reopens at once.
func TestSignalReceiveRetryAtDeviceWakeWhileNothingTicks(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	old := receiveBackoff
	receiveBackoff = func(ctx context.Context) backoff.BackOff {
		return backoff.WithContext(backoff.NewConstantBackOff(10*time.Second), ctx)
	}
	t.Cleanup(func() { receiveBackoff = old })

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: key, ctx: context.Background()}
	fake := &downSignal{}
	c.conn.Swap(lazySignalConn(t), fake, 30*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Receive(ctx, func(*proto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	require.Eventually(t, func() bool { return fake.attempts.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	clk.jump(100 * time.Millisecond)
	w.SetDeviceAsleep(true)
	clk.jump(time.Second)
	w.SetDeviceAsleep(false)
	require.Eventually(t, func() bool { return fake.attempts.Load() == 2 }, time.Second, 5*time.Millisecond,
		"the device wake after a sleep reopens the stream before the wall deadline")
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(2), fake.attempts.Load(), "one attempt per wake")
}
