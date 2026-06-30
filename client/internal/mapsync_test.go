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

// a config-only update arriving while a full map is still converging must keep the
// pending map (so its remaining peer batches still apply); once converged or when the
// pending target has no map, it replaces as usual.
func TestMapStateManager_MergeTargetPreservesPendingMap(t *testing.T) {
	m := newMapStateManager(nil, nil, nil)

	fullMap := &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{Serial: 5}}
	configOnly := &mgmProto.SyncResponse{NetbirdConfig: &mgmProto.NetbirdConfig{}}

	// still converging the full map (targetGen > appliedGen): graft the map onto the
	// incoming config-only update instead of dropping it
	m.targetGen, m.appliedGen = 5, 4
	merged := m.mergeTarget(fullMap, configOnly)
	require.NotNil(t, merged.GetNetworkMap(), "pending map must be preserved")
	require.EqualValues(t, 5, merged.GetNetworkMap().GetSerial())
	require.NotNil(t, merged.GetNetbirdConfig(), "new config must be carried")
	require.NotSame(t, configOnly, merged, "must not mutate the received update in place")

	// already converged (targetGen == appliedGen): nothing pending -> plain replace
	m.targetGen, m.appliedGen = 5, 5
	require.Same(t, configOnly, m.mergeTarget(fullMap, configOnly))

	// a full map always replaces
	newFull := &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{Serial: 6}}
	m.targetGen, m.appliedGen = 5, 4
	require.Same(t, newFull, m.mergeTarget(fullMap, newFull))
}

// converges over the bounded passes (apply returns more until the 3rd pass),
// fires onConverged exactly once, then blocks (no further apply) until a new target.
func TestMapStateManager_ConvergesThenStops(t *testing.T) {
	var passes int32
	var firstPasses int32
	converged := make(chan struct{}, 1)

	apply := func(_ *mgmProto.SyncResponse, firstPass bool) (bool, error) {
		n := atomic.AddInt32(&passes, 1)
		if firstPass {
			atomic.AddInt32(&firstPasses, 1)
		}
		return n < 3, nil // more on pass 1 and 2, converge on pass 3
	}
	m := newMapStateManager(apply, nil, func(time.Duration) { converged <- struct{}{} })

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
	require.EqualValues(t, 1, atomic.LoadInt32(&firstPasses), "firstPass true only on pass 1, false on re-runs of the same target")

	// once converged the loop blocks: no further apply calls
	time.Sleep(100 * time.Millisecond)
	require.EqualValues(t, 3, atomic.LoadInt32(&passes), "apply must not run after convergence")
}

// persist runs once per received update (not per apply pass), regardless of how many
// bounded passes that target takes to converge.
func TestMapStateManager_PersistsOncePerUpdate(t *testing.T) {
	var passes, persists int32
	converged := make(chan struct{}, 1)
	apply := func(_ *mgmProto.SyncResponse, _ bool) (bool, error) {
		n := atomic.AddInt32(&passes, 1)
		return n < 3, nil // 3 passes for one target
	}
	persist := func(*mgmProto.SyncResponse) { atomic.AddInt32(&persists, 1) }
	m := newMapStateManager(apply, persist, func(time.Duration) { converged <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{}))
	select {
	case <-converged:
	case <-time.After(2 * time.Second):
		t.Fatal("did not converge")
	}
	require.EqualValues(t, 3, atomic.LoadInt32(&passes))
	require.EqualValues(t, 1, atomic.LoadInt32(&persists), "persist once per update, not per pass")
}

// every update received from management is persisted — even one that is coalesced /
// skipped from apply before it ever converges.
func TestMapStateManager_PersistsEveryUpdateIncludingSkipped(t *testing.T) {
	release := make(chan struct{})
	var persists int32
	apply := func(_ *mgmProto.SyncResponse, _ bool) (bool, error) {
		<-release // hold the first apply so the second update coalesces/skips
		return false, nil
	}
	persist := func(*mgmProto.SyncResponse) { atomic.AddInt32(&persists, 1) }
	m := newMapStateManager(apply, persist, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)

	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{})) // map1 -> apply blocks
	require.NoError(t, m.SetTarget(&mgmProto.SyncResponse{})) // map2 supersedes map1 (skipped from apply)
	close(release)

	// both updates persisted even though map1 is skipped from apply
	require.Eventually(t, func() bool { return atomic.LoadInt32(&persists) == 2 }, 2*time.Second, 10*time.Millisecond)
}

// each map that is actually processed (converged before the next arrives) fires
// onConverged exactly once — mirroring the legacy per-message handleSync timing.
func TestMapStateManager_SignalsEachProcessedMap(t *testing.T) {
	converged := make(chan struct{}, 8)
	apply := func(_ *mgmProto.SyncResponse, _ bool) (bool, error) {
		return false, nil // converge in one pass
	}
	m := newMapStateManager(apply, nil, func(time.Duration) { converged <- struct{}{} })

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
	apply := func(_ *mgmProto.SyncResponse, _ bool) (bool, error) {
		applies.Add(1)
		<-release // hold the first apply in-flight so we can queue a newer target
		return false, nil
	}
	m := newMapStateManager(apply, nil, func(time.Duration) { converged.Add(1) })

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

	apply := func(_ *mgmProto.SyncResponse, _ bool) (bool, error) {
		applied <- struct{}{}
		if failNext.Load() {
			return false, errors.New("boom")
		}
		return false, nil // converge in one pass
	}
	var converged atomic.Int32
	m := newMapStateManager(apply, nil, func(time.Duration) { converged.Add(1) })

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
	apply := func(_ *mgmProto.SyncResponse, _ bool) (bool, error) {
		applied <- struct{}{}
		return false, nil // converge in one pass
	}
	m := newMapStateManager(apply, nil, nil)

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
