package manager

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/listener"
	"github.com/netbirdio/netbird/client/internal/lazyconn/watcher"
)

type Manager struct {
	watcher      *watcher.Watcher
	listenerMgr  *listener.Manager
	managedPeers map[wgtypes.Key]lazyconn.PeerConfig

	addPeers   chan []lazyconn.PeerConfig
	removePeer chan wgtypes.Key

	watcherWG sync.WaitGroup
	mu        sync.Mutex
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		watcher:      watcher.NewWatcher(wgIface),
		listenerMgr:  listener.NewManager(wgIface),
		managedPeers: make(map[wgtypes.Key]lazyconn.PeerConfig),
		addPeers:     make(chan []lazyconn.PeerConfig, 1),
		removePeer:   make(chan wgtypes.Key, 1),
	}
	return m
}

func (m *Manager) Start() {
	m.mu.Lock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m.watcherWG.Add(1)
	m.mu.Unlock()

	go func() {
		m.watcher.Watch(ctx)
		m.watcherWG.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case peerID := <-m.watcher.PeerTimedOutChan:
			m.mu.Lock()
			cfg, ok := m.managedPeers[peerID]
			if !ok {
				continue
			}

			if err := m.listenerMgr.CreateFakePeers(cfg); err != nil {
				log.Errorf("failed to start watch lazy connection tries: %s", err)
			}
			m.mu.Unlock()
		case peerID := <-m.listenerMgr.TrafficStartChan:
			m.mu.Lock()
			_, ok := m.managedPeers[peerID]
			if !ok {
				continue
			}

			log.Infof("peer %s started to send traffic", peerID)
			m.watcher.AddPeer(peerID)
			m.notifyPeerAction(peerID)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) SetPeer(peer lazyconn.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.managedPeers[peer.PublicKey]; ok {
		return nil
	}

	if err := m.listenerMgr.CreateFakePeers(peer); err != nil {
		return err
	}

	// todo: remove removed peers from the list
	return nil
}

func (m *Manager) RemovePeer(peerID wgtypes.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.watcher.RemovePeer(peerID)
	m.listenerMgr.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.listenerMgr.Close()
	m.watcherWG.Wait()
	m.managedPeers = make(map[wgtypes.Key]lazyconn.PeerConfig)
}

func (m *Manager) notifyPeerAction(peerID wgtypes.Key) {
	// todo notify engine
}
