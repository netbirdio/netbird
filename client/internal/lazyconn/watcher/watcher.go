package watcher

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

const (
	checkPeriod       = 75 * time.Second // 3 * keep alive time (25s)
	expectedMinimumRx = 90 * 2           // 2x keep alive packets
)

type rxHistory struct {
	received int64
}

type Watcher struct {
	PeerTimedOutChan chan wgtypes.Key

	wgIface lazyconn.WGIface

	peers   map[wgtypes.Key]*rxHistory
	peersMu sync.Mutex
}

func NewWatcher(wgIface lazyconn.WGIface) *Watcher {
	return &Watcher{
		PeerTimedOutChan: make(chan wgtypes.Key, 1),
		wgIface:          wgIface,
		peers:            make(map[wgtypes.Key]*rxHistory),
	}
}

func (m *Watcher) Watch(ctx context.Context) {
	timer := time.NewTimer(checkPeriod)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			stats, err := m.wgIface.Transfers()
			if err != nil {
				log.Errorf("failed to get peer stats: %s", err)
				continue
			}
			m.checkTimeouts(ctx, stats)
		}
	}
}

func (m *Watcher) AddPeer(peerID wgtypes.Key) {
	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	m.peers[peerID] = &rxHistory{}
}

func (m *Watcher) RemovePeer(id wgtypes.Key) {
	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	delete(m.peers, id)
}

// Todo: this is a naive implementation, we must to finish it
func (m *Watcher) checkTimeouts(ctx context.Context, allPeersStats map[wgtypes.Key]configurer.WGStats) {
	m.peersMu.Lock()
	defer m.peersMu.Unlock()

	for p, rxh := range m.peers {
		s, ok := allPeersStats[p]
		if !ok {
			log.Warnf("no stats for peer %s", p)
		}

		// received bytes since last check
		received := s.RxBytes - rxh.received
		if received >= expectedMinimumRx {
			rxh.received = s.RxBytes
			continue
		}

		// todo handle that case when swtich from P2P to Relay and the endpoint has been reseted.

		// peer timed out
		delete(m.peers, p)

		select {
		case <-ctx.Done():
			return
		case m.PeerTimedOutChan <- p:
		}
	}
}
