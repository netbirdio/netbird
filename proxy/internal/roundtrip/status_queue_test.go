package roundtrip

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func noopCall(context.Context) error { return nil }

// A snapshot of many services must not cost one management round trip per
// service in sequence.
func TestStatusQueue_SendsInParallel(t *testing.T) {
	const services = 160
	const rtt = 50 * time.Millisecond

	q := newStatusQueue(context.Background(), statusQueueShards, statusQueueDepth)
	t.Cleanup(q.stop)
	var sent atomic.Int32
	call := func(context.Context) error {
		time.Sleep(rtt)
		sent.Add(1)
		return nil
	}

	start := time.Now()
	for i := 0; i < services; i++ {
		id := types.ServiceID(fmt.Sprintf("svc-%d", i))
		require.NoError(t, q.enqueue(context.Background(), statusUpdate{serviceID: id, call: call}), "enqueue %s", id)
	}
	assert.Less(t, time.Since(start), rtt, "enqueue must not wait for management")

	require.Eventually(t, func() bool { return sent.Load() == services }, 5*time.Second, 5*time.Millisecond,
		"every update must be sent")
	assert.Less(t, time.Since(start), services*rtt/4, "updates must be sent concurrently")
}

// Updates for one service reach management in the order they were queued: a
// slow connect is not overtaken by an error or a disconnect queued after it.
func TestStatusQueue_KeepsOrderPerService(t *testing.T) {
	const services = 20
	q := newStatusQueue(context.Background(), statusQueueShards, statusQueueDepth)
	t.Cleanup(q.stop)
	var mu sync.Mutex
	order := map[types.ServiceID][]string{}
	record := func(id types.ServiceID, what string, delay time.Duration) func(context.Context) error {
		return func(context.Context) error {
			time.Sleep(delay)
			mu.Lock()
			order[id] = append(order[id], what)
			mu.Unlock()
			return nil
		}
	}

	for i := 0; i < services; i++ {
		id := types.ServiceID(fmt.Sprintf("svc-%d", i))
		for _, step := range []struct {
			what  string
			delay time.Duration
		}{{"connect", 20 * time.Millisecond}, {"error", 0}, {"disconnect", 0}} {
			require.NoError(t, q.enqueue(context.Background(), statusUpdate{serviceID: id, call: record(id, step.what, step.delay)}),
				"enqueue %s for %s", step.what, id)
		}
	}

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, got := range order {
			n += len(got)
		}
		return n == services*3
	}, 5*time.Second, 5*time.Millisecond, "every update must be sent")

	mu.Lock()
	defer mu.Unlock()
	for id, got := range order {
		assert.Equal(t, []string{"connect", "error", "disconnect"}, got, "order for service %s", id)
	}
}

// Each call runs with its own deadline, so a call that never returns on its own
// is cut off.
func TestStatusQueue_BoundsEachCall(t *testing.T) {
	q := newStatusQueue(context.Background(), 1, 1)
	t.Cleanup(q.stop)
	deadlines := make(chan time.Time, 1)
	require.NoError(t, q.enqueue(context.Background(), statusUpdate{serviceID: "svc", call: func(ctx context.Context) error {
		dl, _ := ctx.Deadline()
		deadlines <- dl
		return nil
	}}), "enqueue")

	select {
	case dl := <-deadlines:
		require.False(t, dl.IsZero(), "the call must get a deadline")
		assert.WithinDuration(t, time.Now().Add(statusCallTimeout), dl, time.Second, "deadline must be statusCallTimeout away")
	case <-time.After(5 * time.Second):
		t.Fatal("the call never ran")
	}
}

// stop ends the workers even while the parent context is still live, and later
// updates are dropped instead of blocking.
func TestStatusQueue_StopWithLiveParent(t *testing.T) {
	q := newStatusQueue(context.Background(), 1, 0)
	started := make(chan struct{})
	require.NoError(t, q.enqueue(context.Background(), statusUpdate{serviceID: "busy", call: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}), "enqueue")
	<-started

	stopped := make(chan struct{})
	go func() { q.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return while a call was in flight")
	}
	q.stop()

	assert.ErrorIs(t, q.enqueue(context.Background(), statusUpdate{serviceID: "late", call: noopCall}), errStatusQueueStopped,
		"a stopped queue drops updates")
}

// A full shard gives up when the caller's context ends, so a cancelled mapping
// batch is not held.
func TestStatusQueue_EnqueueHonoursCallerContext(t *testing.T) {
	q := newStatusQueue(context.Background(), 1, 0)
	t.Cleanup(q.stop)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{})
	require.NoError(t, q.enqueue(context.Background(), statusUpdate{serviceID: "busy", call: func(context.Context) error {
		close(started)
		<-release
		return nil
	}}), "enqueue")
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	assert.ErrorIs(t, q.enqueue(ctx, statusUpdate{serviceID: "next", call: noopCall}), context.DeadlineExceeded,
		"a full shard must give up when the caller's context ends")
}
