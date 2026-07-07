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

func TestWGWatcher_EnableWgWatcher(t *testing.T) {
	checkPeriod = 5 * time.Second
	wgHandshakeOvertime = 1 * time.Second

	mlog := log.WithField("peer", "tet")
	mocWgIface := &MocWgIface{}
	watcher := NewWGWatcher(mlog, mocWgIface, "", newStateDump("peer", mlog, &Status{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	onDisconnected := make(chan struct{}, 1)
	go watcher.EnableWgWatcher(ctx, time.Now(), func() {
		mlog.Infof("onDisconnectedFn")
		onDisconnected <- struct{}{}
	}, func(when time.Time) {
		mlog.Infof("onHandshakeSuccess: %v", when)
	})

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
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		watcher.EnableWgWatcher(ctx, time.Now(), func() {}, func(when time.Time) {})
	}()
	cancel()

	wg.Wait()

	// Re-enable with a new context
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	onDisconnected := make(chan struct{}, 1)
	go watcher.EnableWgWatcher(ctx, time.Now(), func() {
		onDisconnected <- struct{}{}
	}, func(when time.Time) {})

	time.Sleep(2 * time.Second)
	mocWgIface.disconnect()

	select {
	case <-onDisconnected:
	case <-time.After(10 * time.Second):
		t.Errorf("timeout")
	}
}
