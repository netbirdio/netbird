package internal

import (
	"context"
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
