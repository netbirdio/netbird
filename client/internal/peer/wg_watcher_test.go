package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

type MocWgIface struct {
	stop bool
}

func (m *MocWgIface) GetStats() (map[string]configurer.WGStats, error) {
	return map[string]configurer.WGStats{}, nil
}

func (m *MocWgIface) disconnect() {
	m.stop = true
}

type mockHandshakeStats struct {
	mu        sync.Mutex
	handshake time.Time
}

func (m *mockHandshakeStats) GetStats() (map[string]configurer.WGStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]configurer.WGStats{"": {LastHandshake: m.handshake}}, nil
}

func (m *mockHandshakeStats) advance() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handshake = time.Now()
}

// TestWGWatcher_CheckSuccessCallback: onCheckSuccessFn must fire for a fresh
// handshake even when the watcher started with an existing handshake baseline,
// the case where onHandshakeSuccessFn stays silent.
func TestWGWatcher_CheckSuccessCallback(t *testing.T) {
	// checkPeriod bounds how stale a handshake may be before the watcher treats it
	// as a suspended-machine timeout. The first check fires after wgHandshakeOvertime,
	// so keep checkPeriod well above any scheduling jitter to avoid a false timeout
	// converting the expected success into a disconnect on a loaded runner.
	checkPeriod = 1 * time.Minute
	wgHandshakeOvertime = 1 * time.Second

	mlog := log.WithField("peer", "tet")
	// Use an old baseline so advance() yields a strictly newer handshake even on
	// platforms with coarse clock resolution (Windows), where two time.Now() calls
	// microseconds apart can return the same instant and read as a timed-out handshake.
	stats := &mockHandshakeStats{handshake: time.Now().Add(-time.Hour)}
	watcher := NewWGWatcher(mlog, stats, "", newStateDump("peer", mlog, &Status{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.True(t, watcher.PrepareInitialHandshake())

	firstHandshake := make(chan struct{}, 1)
	checkSuccess := make(chan struct{}, 1)
	go watcher.EnableWgWatcher(ctx, time.Now(), func() {}, func(when time.Time) {
		firstHandshake <- struct{}{}
	}, func() {
		select {
		case checkSuccess <- struct{}{}:
		default:
		}
	})

	stats.advance()

	select {
	case <-checkSuccess:
	case <-time.After(10 * time.Second):
		t.Errorf("timeout waiting for check success callback")
	}

	select {
	case <-firstHandshake:
		t.Errorf("first-handshake callback must not fire for a non-zero baseline")
	default:
	}
}

func TestWGWatcher_EnableWgWatcher(t *testing.T) {
	checkPeriod = 5 * time.Second
	wgHandshakeOvertime = 1 * time.Second

	mlog := log.WithField("peer", "tet")
	mocWgIface := &MocWgIface{}
	watcher := NewWGWatcher(mlog, mocWgIface, "", newStateDump("peer", mlog, &Status{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher.PrepareInitialHandshake()

	onDisconnected := make(chan struct{}, 1)
	go watcher.EnableWgWatcher(ctx, time.Now(), func() {
		mlog.Infof("onDisconnectedFn")
		onDisconnected <- struct{}{}
	}, func(when time.Time) {
		mlog.Infof("onHandshakeSuccess: %v", when)
	}, nil)

	// wait for initial reading
	time.Sleep(2 * time.Second)
	mocWgIface.disconnect()

	select {
	case <-onDisconnected:
	case <-time.After(10 * time.Second):
		t.Errorf("timeout")
	}
}

func TestWGWatcher_ReEnable(t *testing.T) {
	checkPeriod = 5 * time.Second
	wgHandshakeOvertime = 1 * time.Second

	mlog := log.WithField("peer", "tet")
	mocWgIface := &MocWgIface{}
	watcher := NewWGWatcher(mlog, mocWgIface, "", newStateDump("peer", mlog, &Status{}))

	ctx, cancel := context.WithCancel(context.Background())
	watcher.PrepareInitialHandshake()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		watcher.EnableWgWatcher(ctx, time.Now(), func() {}, func(when time.Time) {}, nil)
	}()
	cancel()

	wg.Wait()

	// Re-enable with a new context
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	watcher.PrepareInitialHandshake()

	onDisconnected := make(chan struct{}, 1)
	go watcher.EnableWgWatcher(ctx, time.Now(), func() {
		onDisconnected <- struct{}{}
	}, func(when time.Time) {}, nil)

	time.Sleep(2 * time.Second)
	mocWgIface.disconnect()

	select {
	case <-onDisconnected:
	case <-time.After(10 * time.Second):
		t.Errorf("timeout")
	}
}
