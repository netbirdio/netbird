package controller

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

var (
	_ peerliveness.Store      = store.Store(nil)
	_ peerliveness.Store      = (*store.SqlStore)(nil)
	_ peerliveness.Controller = (*Controller)(nil)
)

type idLog struct {
	mu  sync.Mutex
	ids []string
}

func (r *idLog) add(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
}

func (r *idLog) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}

// newController returns a controller on a mock store whose RegisterInstance calls are recorded.
func newController(t *testing.T) (*Controller, *peerliveness.MockStore, *idLog) {
	t.Helper()
	st := peerliveness.NewMockStore(gomock.NewController(t))
	regs := &idLog{}
	st.EXPECT().RegisterInstance(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, id, _ string) error {
			regs.add(id)
			return nil
		}).AnyTimes()
	return NewController(st), st, regs
}

// requireBlockedOnMutex waits until a goroutine is parked acquiring a sync.RWMutex through
// the given Controller method, so the test knows that goroutine reached the lock.
func requireBlockedOnMutex(t *testing.T, method, lockFrame string) {
	t.Helper()
	require.Eventually(t, func() bool {
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		for _, g := range strings.Split(string(buf), "\n\n") {
			if strings.Contains(g, lockFrame) && strings.Contains(g, method) {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond)
}

func noStaleInstances(st *peerliveness.MockStore) {
	st.EXPECT().ListStaleInstances(gomock.Any()).Return(nil, nil).AnyTimes()
}

// startedController returns a controller that is started on a mock store with no stale
// instances and released when the test ends.
func startedController(t *testing.T) (*Controller, *peerliveness.MockStore) {
	t.Helper()
	c, st, _ := newController(t)
	noStaleInstances(st)
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() {
		st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
	return c, st
}

func TestController_StartRegistersAndSweeps(t *testing.T) {
	c, st, regs := newController(t)
	lastSeen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	st.EXPECT().ListStaleInstances(gomock.Any()).DoAndReturn(func(context.Context) ([]nbpeer.ManagementInstance, error) {
		return []nbpeer.ManagementInstance{
			{ID: regs.all()[0], LastSeen: lastSeen},
			{ID: "dead", LastSeen: lastSeen},
		}, nil
	})
	gomock.InOrder(
		st.EXPECT().SweepInstanceChunk(gomock.Any(), "dead", lastSeen, 1000).Return(1000, nil),
		st.EXPECT().SweepInstanceChunk(gomock.Any(), "dead", lastSeen, 1000).Return(400, nil),
		st.EXPECT().SweepInstanceChunk(gomock.Any(), "dead", lastSeen, 1000).Return(0, nil),
		st.EXPECT().DeleteInstanceIfStale(gomock.Any(), "dead").Return(true, nil),
	)

	require.NoError(t, c.Start(context.Background()))
	require.Len(t, regs.all(), 1)
	assert.Equal(t, regs.all()[0], c.InstanceID())
	assert.NotEmpty(t, c.InstanceID())

	st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(nil)
	require.NoError(t, c.Release(context.Background()))
}

func TestController_StartSweepErrorsDoNotFail(t *testing.T) {
	c, st, _ := newController(t)
	lastSeen := time.Now()

	st.EXPECT().ListStaleInstances(gomock.Any()).Return([]nbpeer.ManagementInstance{
		{ID: "broken", LastSeen: lastSeen},
		{ID: "dead", LastSeen: lastSeen},
	}, nil)
	st.EXPECT().SweepInstanceChunk(gomock.Any(), "broken", lastSeen, 1000).Return(0, errors.New("boom"))
	st.EXPECT().SweepInstanceChunk(gomock.Any(), "dead", lastSeen, 1000).Return(0, nil)
	st.EXPECT().DeleteInstanceIfStale(gomock.Any(), "dead").Return(true, nil)

	require.NoError(t, c.Start(context.Background()))

	st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(nil)
	require.NoError(t, c.Release(context.Background()))
}

func TestController_StartRegisterFailure(t *testing.T) {
	st := peerliveness.NewMockStore(gomock.NewController(t))
	st.EXPECT().RegisterInstance(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("boom"))

	c := NewController(st)
	require.Error(t, c.Start(context.Background()))
	assert.Empty(t, c.InstanceID())
	require.NoError(t, c.Release(context.Background()))
}

func TestController_StartTwice(t *testing.T) {
	c, st, _ := newController(t)
	noStaleInstances(st)

	require.NoError(t, c.Start(context.Background()))
	require.Error(t, c.Start(context.Background()))

	st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(nil)
	require.NoError(t, c.Release(context.Background()))
}

func TestController_HeartbeatKeepsInstance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, regs := newController(t)
		noStaleInstances(st)
		beats := &idLog{}
		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, id string) (bool, error) {
			beats.add(id)
			return true, nil
		}).Times(3)

		require.NoError(t, c.Start(context.Background()))
		id := c.InstanceID()

		time.Sleep(3*nbpeer.HeartbeatInterval + time.Second)
		synctest.Wait()

		assert.Equal(t, id, c.InstanceID())
		assert.Equal(t, []string{id}, regs.all())
		assert.Equal(t, []string{id, id, id}, beats.all())

		st.EXPECT().ReleaseInstance(gomock.Any(), id).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_HeartbeatErrorKeepsLooping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, regs := newController(t)
		noStaleInstances(st)
		gomock.InOrder(
			st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).Return(false, errors.New("boom")),
			st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).Return(true, nil),
		)

		require.NoError(t, c.Start(context.Background()))
		id := c.InstanceID()

		time.Sleep(2*nbpeer.HeartbeatInterval + time.Second)
		synctest.Wait()

		assert.Equal(t, []string{id}, regs.all())

		st.EXPECT().ReleaseInstance(gomock.Any(), id).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_HeartbeatLapseReRegistersPeers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, regs := newController(t)
		noStaleInstances(st)

		var got []types.PeerSession
		var gotID string
		var heartbeatID string
		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, id string) (bool, error) {
			heartbeatID = id
			return false, nil
		})
		st.EXPECT().ReRegisterPeers(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, id string, sessions []types.PeerSession) error {
				gotID, got = id, sessions
				return nil
			})

		require.NoError(t, c.Start(context.Background()))
		oldID := c.InstanceID()

		st.EXPECT().ConnectPeer(gomock.Any(), "acc-1", "peer-1", oldID, int64(10)).Return(true, nil)
		st.EXPECT().ConnectPeer(gomock.Any(), "acc-2", "peer-2", oldID, int64(20)).Return(true, nil)
		st.EXPECT().ConnectPeer(gomock.Any(), "acc-1", "peer-3", oldID, int64(30)).Return(false, nil)
		for _, p := range []struct {
			account, peer string
			session       int64
		}{{"acc-1", "peer-1", 10}, {"acc-2", "peer-2", 20}, {"acc-1", "peer-3", 30}} {
			_, err := c.Connect(context.Background(), st, p.account, p.peer, p.session)
			require.NoError(t, err)
		}

		time.Sleep(nbpeer.HeartbeatInterval + time.Second)
		synctest.Wait()

		newID := c.InstanceID()
		assert.NotEqual(t, oldID, newID)
		assert.Equal(t, oldID, heartbeatID)
		assert.Equal(t, []string{oldID, newID}, regs.all())
		assert.Equal(t, newID, gotID)
		assert.ElementsMatch(t, []types.PeerSession{
			{AccountID: "acc-1", PeerID: "peer-1", SessionStartedAt: 10},
			{AccountID: "acc-2", PeerID: "peer-2", SessionStartedAt: 20},
		}, got)

		st.EXPECT().ReleaseInstance(gomock.Any(), newID).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_FailedReRegisterPeersIsRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, regs := newController(t)
		noStaleInstances(st)

		beats := &idLog{}
		reRegisters := &idLog{}
		var mu sync.Mutex
		var reRegisterSessions [][]types.PeerSession
		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, id string) (bool, error) {
				beats.add(id)
				return len(beats.all()) > 1, nil
			}).AnyTimes()
		st.EXPECT().ReRegisterPeers(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, id string, sessions []types.PeerSession) error {
				reRegisters.add(id)
				mu.Lock()
				defer mu.Unlock()
				reRegisterSessions = append(reRegisterSessions, sessions)
				if len(reRegisterSessions) == 1 {
					return errors.New("boom")
				}
				return nil
			}).AnyTimes()

		require.NoError(t, c.Start(context.Background()))
		oldID := c.InstanceID()

		st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", oldID, int64(10)).Return(true, nil)
		_, err := c.Connect(context.Background(), st, "acc", "peer", 10)
		require.NoError(t, err)

		time.Sleep(3*nbpeer.HeartbeatInterval + time.Second)
		synctest.Wait()

		newID := c.InstanceID()
		require.NotEqual(t, oldID, newID)
		assert.Equal(t, []string{oldID, newID, newID}, beats.all())
		assert.Equal(t, []string{newID, newID}, reRegisters.all(), "the failed re-registration is retried once, then stops")
		assert.Equal(t, []string{oldID, newID}, regs.all())
		sessions := []types.PeerSession{{AccountID: "acc", PeerID: "peer", SessionStartedAt: 10}}
		mu.Lock()
		assert.Equal(t, [][]types.PeerSession{sessions, sessions}, reRegisterSessions)
		mu.Unlock()

		st.EXPECT().ReleaseInstance(gomock.Any(), newID).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_SweepSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, _ := newController(t)

		var mu sync.Mutex
		var ticks int
		var sweptAtTick []int
		var sweepAt []time.Duration
		start := time.Now()

		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			ticks++
			return ticks != 5, nil
		}).AnyTimes()
		st.EXPECT().ReRegisterPeers(gomock.Any(), gomock.Any(), gomock.Len(0)).Return(nil)
		st.EXPECT().ListStaleInstances(gomock.Any()).DoAndReturn(func(context.Context) ([]nbpeer.ManagementInstance, error) {
			mu.Lock()
			defer mu.Unlock()
			sweptAtTick = append(sweptAtTick, ticks)
			sweepAt = append(sweepAt, time.Since(start))
			return nil, nil
		}).AnyTimes()

		require.NoError(t, c.Start(context.Background()))

		time.Sleep(7*nbpeer.HeartbeatInterval + time.Second)
		synctest.Wait()

		mu.Lock()
		assert.Equal(t, 7, ticks)
		assert.Equal(t, []int{0, 7}, sweptAtTick, "startup sweep, then tick 7: tick 5 lapsed and tick 6 follows the gap")
		assert.Equal(t, []time.Duration{0, 7 * nbpeer.HeartbeatInterval}, sweepAt)
		mu.Unlock()

		st.EXPECT().ReleaseInstance(gomock.Any(), gomock.Any()).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_SweepEveryStaleAfter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, _ := newController(t)

		var mu sync.Mutex
		var sweepAt []time.Duration
		start := time.Now()
		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
		st.EXPECT().ListStaleInstances(gomock.Any()).DoAndReturn(func(context.Context) ([]nbpeer.ManagementInstance, error) {
			mu.Lock()
			defer mu.Unlock()
			sweepAt = append(sweepAt, time.Since(start))
			return nil, nil
		}).AnyTimes()

		require.NoError(t, c.Start(context.Background()))

		time.Sleep(2*nbpeer.StaleAfter + time.Second)
		synctest.Wait()

		mu.Lock()
		assert.Equal(t, []time.Duration{0, nbpeer.StaleAfter, 2 * nbpeer.StaleAfter}, sweepAt)
		mu.Unlock()

		st.EXPECT().ReleaseInstance(gomock.Any(), gomock.Any()).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_SweepSkipsOwnInstance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, regs := newController(t)
		lastSeen := time.Now()

		var mu sync.Mutex
		var lists int
		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
		st.EXPECT().ListStaleInstances(gomock.Any()).DoAndReturn(func(context.Context) ([]nbpeer.ManagementInstance, error) {
			mu.Lock()
			defer mu.Unlock()
			lists++
			if lists == 1 {
				return nil, nil
			}
			return []nbpeer.ManagementInstance{
				{ID: regs.all()[0], LastSeen: lastSeen},
				{ID: "dead", LastSeen: lastSeen},
			}, nil
		}).AnyTimes()
		gomock.InOrder(
			st.EXPECT().SweepInstanceChunk(gomock.Any(), "dead", lastSeen, 1000).Return(7, nil),
			st.EXPECT().SweepInstanceChunk(gomock.Any(), "dead", lastSeen, 1000).Return(0, nil),
			st.EXPECT().DeleteInstanceIfStale(gomock.Any(), "dead").Return(true, nil),
		)

		require.NoError(t, c.Start(context.Background()))
		id := c.InstanceID()

		time.Sleep(nbpeer.StaleAfter + time.Second)
		synctest.Wait()

		st.EXPECT().ReleaseInstance(gomock.Any(), id).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

func TestController_DisconnectFencesRegistry(t *testing.T) {
	c, st := startedController(t)
	ctx := context.Background()

	st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", gomock.Any(), int64(5)).Return(true, nil)
	applied, err := c.Connect(ctx, st, "acc", "peer", 5)
	require.NoError(t, err)
	require.True(t, applied)

	st.EXPECT().DisconnectPeer(gomock.Any(), "peer", int64(3)).Return(false, nil)
	deleted, err := c.Disconnect(ctx, st, "peer", 3)
	require.NoError(t, err)
	assert.False(t, deleted)
	assert.Equal(t, connection{accountID: "acc", session: 5}, c.registry["peer"])

	st.EXPECT().DisconnectPeer(gomock.Any(), "peer", int64(5)).Return(false, errors.New("boom"))
	_, err = c.Disconnect(ctx, st, "peer", 5)
	require.Error(t, err)
	assert.Contains(t, c.registry, "peer")

	st.EXPECT().DisconnectPeer(gomock.Any(), "peer", int64(5)).Return(true, nil)
	deleted, err = c.Disconnect(ctx, st, "peer", 5)
	require.NoError(t, err)
	assert.True(t, deleted)
	assert.NotContains(t, c.registry, "peer")
}

func TestController_ReleaseConnectionClearsRegistry(t *testing.T) {
	c, st := startedController(t)
	ctx := context.Background()

	st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", gomock.Any(), int64(5)).Return(true, nil)
	_, err := c.Connect(ctx, st, "acc", "peer", 5)
	require.NoError(t, err)

	st.EXPECT().ReleasePeerConnection(gomock.Any(), "peer").Return(errors.New("boom"))
	require.Error(t, c.ReleaseConnection(ctx, st, "peer"))
	assert.Contains(t, c.registry, "peer", "a failed release keeps the registry entry")

	txStore := peerliveness.NewMockStore(gomock.NewController(t))
	txStore.EXPECT().ReleasePeerConnection(gomock.Any(), "peer").Return(nil)
	require.NoError(t, c.ReleaseConnection(ctx, txStore, "peer"))
	assert.NotContains(t, c.registry, "peer")
}

func TestController_ForgetPeerDropsOnlyThatPeer(t *testing.T) {
	c, st := startedController(t)

	for _, peerID := range []string{"peer-1", "peer-2"} {
		st.EXPECT().ConnectPeer(gomock.Any(), "acc", peerID, gomock.Any(), int64(5)).Return(true, nil)
		_, err := c.Connect(context.Background(), st, "acc", peerID, 5)
		require.NoError(t, err)
	}

	c.ForgetPeer("peer-1")

	assert.NotContains(t, c.registry, "peer-1")
	assert.Contains(t, c.registry, "peer-2")
}

func TestController_ForgetAccountDropsOnlyThatAccount(t *testing.T) {
	c, st := startedController(t)

	for _, p := range []struct{ account, peer string }{{"acc-1", "peer-1"}, {"acc-1", "peer-2"}, {"acc-2", "peer-3"}} {
		st.EXPECT().ConnectPeer(gomock.Any(), p.account, p.peer, gomock.Any(), int64(5)).Return(true, nil)
		_, err := c.Connect(context.Background(), st, p.account, p.peer, 5)
		require.NoError(t, err)
	}

	c.ForgetAccount("acc-1")

	assert.Equal(t, map[string]connection{"peer-3": {accountID: "acc-2", session: 5}}, c.registry)
}

func TestController_SweepDrainsOrphanedInstances(t *testing.T) {
	c, st, regs := newController(t)

	st.EXPECT().ListStaleInstances(gomock.Any()).DoAndReturn(func(context.Context) ([]nbpeer.ManagementInstance, error) {
		return []nbpeer.ManagementInstance{{ID: regs.all()[0]}, {ID: "orphan"}}, nil
	})
	gomock.InOrder(
		st.EXPECT().SweepInstanceChunk(gomock.Any(), "orphan", time.Time{}, 1000).Return(3, nil),
		st.EXPECT().SweepInstanceChunk(gomock.Any(), "orphan", time.Time{}, 1000).Return(0, nil),
		st.EXPECT().DeleteInstanceIfStale(gomock.Any(), "orphan").Return(false, nil),
	)

	require.NoError(t, c.Start(context.Background()))

	st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(nil)
	require.NoError(t, c.Release(context.Background()))
}

func TestController_ConnectNotAppliedLeavesRegistry(t *testing.T) {
	c, st := startedController(t)

	st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", gomock.Any(), int64(5)).Return(false, nil)
	applied, err := c.Connect(context.Background(), st, "acc", "peer", 5)
	require.NoError(t, err)
	assert.False(t, applied)

	st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", gomock.Any(), int64(6)).Return(false, errors.New("boom"))
	_, err = c.Connect(context.Background(), st, "acc", "peer", 6)
	require.Error(t, err)

	assert.Empty(t, c.registry)
}

func TestController_ConnectBeforeStartFails(t *testing.T) {
	c, st, _ := newController(t)

	applied, err := c.Connect(context.Background(), st, "acc", "peer", 5)
	require.Error(t, err)
	assert.False(t, applied)
	assert.Empty(t, c.registry)
}

func TestController_ConnectUsesGivenStore(t *testing.T) {
	c, _ := startedController(t)
	txStore := peerliveness.NewMockStore(gomock.NewController(t))

	txStore.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", gomock.Any(), int64(5)).Return(true, nil)
	txStore.EXPECT().DisconnectPeer(gomock.Any(), "peer", int64(5)).Return(true, nil)

	_, err := c.Connect(context.Background(), txStore, "acc", "peer", 5)
	require.NoError(t, err)
	_, err = c.Disconnect(context.Background(), txStore, "peer", 5)
	require.NoError(t, err)
}

func TestController_ReleaseStopsLoopAndReleasesCurrentID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, _ := newController(t)
		noStaleInstances(st)
		st.EXPECT().HeartbeatInstance(gomock.Any(), gomock.Any()).Return(false, nil)
		st.EXPECT().ReRegisterPeers(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		require.NoError(t, c.Start(context.Background()))
		oldID := c.InstanceID()

		time.Sleep(nbpeer.HeartbeatInterval + time.Second)
		synctest.Wait()
		newID := c.InstanceID()
		require.NotEqual(t, oldID, newID)

		st.EXPECT().ReleaseInstance(gomock.Any(), newID).Return(nil)
		require.NoError(t, c.Release(context.Background()))

		// Any further heartbeat would hit an unexpected mock call.
		time.Sleep(3 * nbpeer.HeartbeatInterval)
		synctest.Wait()
	})
}

func TestController_ReleaseError(t *testing.T) {
	c, st, _ := newController(t)
	noStaleInstances(st)
	require.NoError(t, c.Start(context.Background()))

	st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(errors.New("boom"))
	require.Error(t, c.Release(context.Background()))
}

func TestController_ContextCancelStopsLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, st, _ := newController(t)
		noStaleInstances(st)
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, c.Start(ctx))

		cancel()
		synctest.Wait()

		time.Sleep(3 * nbpeer.HeartbeatInterval)
		synctest.Wait()

		st.EXPECT().ReleaseInstance(gomock.Any(), c.InstanceID()).Return(nil)
		require.NoError(t, c.Release(context.Background()))
	})
}

// A Connect that already read the old instance ID must have registered its peer before
// re-registration snapshots the registry, otherwise its row would stay under the old ID.
func TestController_ReRegistrationWaitsForInFlightConnect(t *testing.T) {
	c, st, regs := newController(t)
	noStaleInstances(st)
	require.NoError(t, c.Start(context.Background()))
	oldID := c.InstanceID()

	inConnect := make(chan struct{})
	finishConnect := make(chan struct{})
	st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", oldID, int64(9)).
		DoAndReturn(func(context.Context, string, string, string, int64) (bool, error) {
			close(inConnect)
			<-finishConnect
			return true, nil
		})

	var reRegistered []types.PeerSession
	var reRegisteredID string
	reRegisterCalled := make(chan struct{})
	st.EXPECT().ReRegisterPeers(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, id string, sessions []types.PeerSession) error {
			close(reRegisterCalled)
			reRegisteredID, reRegistered = id, sessions
			return nil
		})

	var wg sync.WaitGroup
	wg.Go(func() {
		applied, err := c.Connect(context.Background(), st, "acc", "peer", 9)
		assert.NoError(t, err)
		assert.True(t, applied)
	})
	<-inConnect

	wg.Go(func() {
		assert.NoError(t, c.reRegister(context.Background()))
	})
	requireBlockedOnMutex(t, "(*Controller).reRegister", "sync.(*RWMutex).Lock")
	select {
	case <-reRegisterCalled:
		t.Fatal("re-registration ran while a Connect was in flight")
	default:
	}
	close(finishConnect)
	wg.Wait()

	newID := c.InstanceID()
	require.NotEqual(t, oldID, newID)
	assert.Equal(t, []string{oldID, newID}, regs.all())
	assert.Equal(t, newID, reRegisteredID)
	assert.Equal(t, []types.PeerSession{{AccountID: "acc", PeerID: "peer", SessionStartedAt: 9}}, reRegistered)

	st.EXPECT().ReleaseInstance(gomock.Any(), newID).Return(nil)
	require.NoError(t, c.Release(context.Background()))
}

// A Connect that starts during re-registration must write under the new ID.
func TestController_ConnectDuringReRegistrationUsesNewID(t *testing.T) {
	c, st, _ := newController(t)
	noStaleInstances(st)
	require.NoError(t, c.Start(context.Background()))

	inReRegister := make(chan struct{})
	finishReRegister := make(chan struct{})
	st.EXPECT().ReRegisterPeers(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string, []types.PeerSession) error {
			close(inReRegister)
			<-finishReRegister
			return nil
		})

	var wg sync.WaitGroup
	wg.Go(func() {
		assert.NoError(t, c.reRegister(context.Background()))
	})
	<-inReRegister
	newID := c.id

	var connectedUnder string
	st.EXPECT().ConnectPeer(gomock.Any(), "acc", "peer", gomock.Any(), int64(9)).
		DoAndReturn(func(_ context.Context, _, _, instanceID string, _ int64) (bool, error) {
			connectedUnder = instanceID
			return true, nil
		})
	wg.Go(func() {
		_, err := c.Connect(context.Background(), st, "acc", "peer", 9)
		assert.NoError(t, err)
	})
	requireBlockedOnMutex(t, "(*Controller).Connect", "sync.(*RWMutex).RLock")
	close(finishReRegister)
	wg.Wait()

	assert.Equal(t, newID, connectedUnder)

	st.EXPECT().ReleaseInstance(gomock.Any(), newID).Return(nil)
	require.NoError(t, c.Release(context.Background()))
}
