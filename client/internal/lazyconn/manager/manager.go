package manager

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/lazyconn/listener"
	"github.com/netbirdio/netbird/client/internal/lazyconn/watcher"
)

type Manager struct {
	PeerActivityChan chan string

	watcher      *watcher.Watcher
	listenerMgr  *listener.Manager
	managedPeers map[string]lazyconn.PeerConfig

	watcherWG sync.WaitGroup
	mu        sync.Mutex
}

func NewManager(wgIface lazyconn.WGIface) *Manager {
	m := &Manager{
		PeerActivityChan: make(chan string, 1),
		watcher:          watcher.NewWatcher(wgIface),
		listenerMgr:      listener.NewManager(wgIface),
		managedPeers:     make(map[string]lazyconn.PeerConfig),
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
				m.mu.Unlock()
				continue
			}

			if err := m.listenerMgr.CreateFakePeer(cfg); err != nil {
				log.Errorf("failed to start watch lazy connection tries: %s", err)
			}
			m.mu.Unlock()
		case peerID := <-m.listenerMgr.TrafficStartChan:
			m.mu.Lock()
			_, ok := m.managedPeers[peerID]
			if !ok {
				log.Debugf("lazy peer is not managed: %s", peerID)
				m.mu.Unlock()
				continue
			}

			//m.watcher.AddPeer(peerID)
			log.Infof("lazy peer is active: %s", peerID)
			m.notifyPeerAction(ctx, peerID)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) AddPeer(peer lazyconn.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Debugf("adding lazy peer: %s", peer.PublicKey)

	if _, ok := m.managedPeers[peer.PublicKey]; ok {
		return nil
	}

	if err := m.listenerMgr.CreateFakePeer(peer); err != nil {
		return err
	}

	m.managedPeers[peer.PublicKey] = peer
	return nil
}

func (m *Manager) RemovePeer(peerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.managedPeers[peerID]; !ok {
		return false
	}

	log.Debugf("removing lazy peer: %s", peerID)

	m.watcher.RemovePeer(peerID)
	m.listenerMgr.RemovePeer(peerID)
	delete(m.managedPeers, peerID)
	return false
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.listenerMgr.Close()
	m.watcherWG.Wait()
	m.managedPeers = make(map[string]lazyconn.PeerConfig)
}

func (m *Manager) notifyPeerAction(ctx context.Context, peerID string) {
	select {
	case <-ctx.Done():
	case m.PeerActivityChan <- peerID:
	}
}
