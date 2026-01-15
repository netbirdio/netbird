package peer

import (
	"context"
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
	watcher := NewWGWatcher(mlog, mocWgIface, "", newStateDump("peer", mlog, &Status{}), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	onDisconnected := make(chan struct{}, 1)
	go watcher.EnableWgWatcher(ctx, func() {
		mlog.Infof("onDisconnectedFn")
		onDisconnected <- struct{}{}
	})

	// wait for initial reading
	time.Sleep(2 * time.Second)
	mocWgIface.disconnect()

	select {
	case <-onDisconnected:
	case <-time.After(10 * time.Second):
		t.Errorf("timeout")
	}
	watcher.DisableWgWatcher()
}

func TestWGWatcher_ReEnable(t *testing.T) {
	checkPeriod = 5 * time.Second
	wgHandshakeOvertime = 1 * time.Second

	mlog := log.WithField("peer", "tet")
	mocWgIface := &MocWgIface{}
	watcher := NewWGWatcher(mlog, mocWgIface, "", newStateDump("peer", mlog, &Status{}), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	onDisconnected := make(chan struct{}, 1)

	go watcher.EnableWgWatcher(ctx, func() {})
	time.Sleep(1 * time.Second)
	watcher.DisableWgWatcher()

	go watcher.EnableWgWatcher(ctx, func() {
		onDisconnected <- struct{}{}
	})

	time.Sleep(2 * time.Second)
	mocWgIface.disconnect()

	select {
	case <-onDisconnected:
	case <-time.After(10 * time.Second):
		t.Errorf("timeout")
	}
	watcher.DisableWgWatcher()
}
