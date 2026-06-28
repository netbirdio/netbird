package internal

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// converges over the bounded passes (apply returns more until the 3rd pass),
// fires onConverged exactly once, then blocks (no further apply) until a new target.
func TestMapStateManager_ConvergesThenStops(t *testing.T) {
	var passes int32
	converged := make(chan struct{}, 1)

	apply := func(*mgmProto.SyncResponse) (bool, error) {
		n := atomic.AddInt32(&passes, 1)
		return n < 3, nil // more on pass 1 and 2, converge on pass 3
	}
	m := newMapStateManager(apply, func(time.Duration) { converged <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))

	select {
	case <-converged:
	case <-time.After(2 * time.Second):
		t.Fatal("manager did not converge")
	}
	require.EqualValues(t, 3, atomic.LoadInt32(&passes))

	// once converged the loop blocks: no further apply calls
	time.Sleep(100 * time.Millisecond)
	require.EqualValues(t, 3, atomic.LoadInt32(&passes), "apply must not run after convergence")
}

// each map that is actually processed (converged before the next arrives) fires
// onConverged exactly once — mirroring the legacy per-message handleSync timing.
func TestMapStateManager_SignalsEachProcessedMap(t *testing.T) {
	converged := make(chan struct{}, 8)
	apply := func(*mgmProto.SyncResponse) (bool, error) {
		return false, nil // converge in one pass
	}
	m := newMapStateManager(apply, func(time.Duration) { converged <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	const maps = 3
	for i := 0; i < maps; i++ {
		require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
		select { // wait for this map to converge before sending the next (no coalescing)
		case <-converged:
		case <-time.After(2 * time.Second):
			t.Fatalf("map %d not signaled", i)
		}
	}

	// no extra signals once the stream goes quiet
	select {
	case <-converged:
		t.Fatal("unexpected extra onConverged")
	case <-time.After(100 * time.Millisecond):
	}
}

// a map superseded before it converges is skipped: only the latest (processed) map
// fires onConverged, not the skipped one.
func TestMapStateManager_SkippedMapNotSignaled(t *testing.T) {
	release := make(chan struct{})
	var applies, converged atomic.Int32
	apply := func(*mgmProto.SyncResponse) (bool, error) {
		applies.Add(1)
		<-release // hold the first apply in-flight so we can queue a newer target
		return false, nil
	}
	m := newMapStateManager(apply, func(time.Duration) { converged.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	// map1 is picked up; its apply blocks on release
	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	require.Eventually(t, func() bool { return applies.Load() >= 1 }, 2*time.Second, 5*time.Millisecond)

	// map2 supersedes map1 before it settled -> map1 is skipped
	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	close(release) // let both applies proceed

	// only the processed (latest) map signals; the skipped one does not
	require.Eventually(t, func() bool { return converged.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	require.EqualValues(t, 1, converged.Load(), "skipped map must not fire onConverged")
	require.EqualValues(t, 2, applies.Load(), "both targets entered apply (map1 once, map2 once)")
}

// an apply error drops the target: no retry of the same target, no onConverged,
// the loop goes idle — and a fresh target is still applied afterwards.
func TestMapStateManager_DropsTargetOnError(t *testing.T) {
	applied := make(chan struct{}, 8)
	var failNext atomic.Bool
	failNext.Store(true)

	apply := func(*mgmProto.SyncResponse) (bool, error) {
		applied <- struct{}{}
		if failNext.Load() {
			return false, errors.New("boom")
		}
		return false, nil // converge in one pass
	}
	var converged atomic.Int32
	m := newMapStateManager(apply, func(time.Duration) { converged.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	// first target errors -> applied once, then dropped (no retry, no onConverged)
	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("errored target not applied")
	}
	select {
	case <-applied:
		t.Fatal("errored target must not be retried")
	case <-time.After(150 * time.Millisecond):
	}
	require.EqualValues(t, 0, converged.Load(), "onConverged must not fire on error")

	// a new target is still processed normally and converges
	failNext.Store(false)
	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("new target after error not applied")
	}
	require.Eventually(t, func() bool { return converged.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
}

// a new target after convergence triggers a fresh apply; an idle (converged)
// manager does not apply on its own.
func TestMapStateManager_ReappliesOnNewTarget(t *testing.T) {
	applied := make(chan struct{}, 8)
	apply := func(*mgmProto.SyncResponse) (bool, error) {
		applied <- struct{}{}
		return false, nil // converge in one pass
	}
	m := newMapStateManager(apply, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("first target not applied")
	}

	// converged → must stay idle (no spurious apply)
	select {
	case <-applied:
		t.Fatal("unexpected apply while idle/converged")
	case <-time.After(150 * time.Millisecond):
	}

	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("new target not applied")
	}
}
