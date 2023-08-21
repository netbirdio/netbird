package ephemeral

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
)

const (
	ephemeralLifeTime = 10 * time.Minute
)

type prop struct {
	account  *server.Account
	deadline time.Time
}

type Manager struct {
	store server.Store

	// todo handle thread safe way
	peers        map[string]prop
	uptimeTicker *time.Ticker
	doneTicker   chan struct{}
}

func NewManager(store server.Store) *Manager {
	return &Manager{
		store:      store,
		peers:      make(map[string]prop),
		doneTicker: make(chan struct{}),
	}
}

func (e *Manager) Start() {
	e.loadEphemeralPeers()
	e.startCleanupLoop()
}

func (e *Manager) Stop() {
	select {
	case e.doneTicker <- struct{}{}:
	default:
	}
}

func (e *Manager) OnPeerConnected(peer *server.Peer) {
	if !peer.Ephemeral {
		return
	}

	delete(e.peers, peer.ID)
}

func (e *Manager) OnPeerDisconnected(peer *server.Peer) {
	if !peer.Ephemeral {
		return
	}

	a, err := e.store.GetAccountByPeerID(peer.ID)
	if err != nil {
		log.Errorf("failed to add peer to ephemeral list: %s", err)
		return
	}

	e.addPeer(peer.ID, a)
}

func (e *Manager) loadEphemeralPeers() {
	accounts := e.store.GetAllAccounts()
	t := newDeadLine()
	for _, a := range accounts {
		for id, p := range a.Peers {
			if p.Ephemeral {
				e.peers[id] = prop{
					a, t,
				}
			}
		}
	}
	log.Debugf("loaded %d ephemeral peers", len(e.peers))
}

func (e *Manager) startCleanupLoop() {
	e.uptimeTicker = time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-e.uptimeTicker.C:
			e.cleanup()
		case <-e.doneTicker:
			e.uptimeTicker.Stop()
			return
		}
	}
}

func (e *Manager) cleanup() {
	now := time.Now()
	for id, p := range e.peers {
		if now.Before(p.deadline) {
			continue
		}

		p.account.DeletePeer(id)
		delete(e.peers, id)
	}
}

func (e *Manager) addPeer(peerId string, account *server.Account) {
	e.peers[peerId] = prop{
		account,
		newDeadLine(),
	}
}

func newDeadLine() time.Time {
	return time.Now().Add(ephemeralLifeTime)
}
