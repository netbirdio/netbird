package server

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	ephemeralLifeTime = 10 * time.Minute
)

var (
	timeNow      = time.Now
	tickerPeriod = 1 * time.Minute
)

type prop struct {
	account  *Account
	deadline time.Time
}

// todo: consider to remove peer from ephemeral list when the peer has been deleted via API

type EphemeralManager struct {
	store          Store
	accountManager AccountManager

	peers        map[string]prop
	peersLock    sync.Mutex
	uptimeTicker *time.Ticker
	doneTicker   chan struct{}
}

// NewEphemeralManager instantiate new EphemeralManager
func NewEphemeralManager(store Store, accountManager AccountManager) *EphemeralManager {
	return &EphemeralManager{
		store:          store,
		accountManager: accountManager,
		peers:          make(map[string]prop),
		doneTicker:     make(chan struct{}),
	}
}

// Start the ephemeral cleanup loop. Periodically check the list of inactive peers.
// After the peer reach the timeout period it will be deleted from the system.
func (e *EphemeralManager) Start() {
	if e.uptimeTicker != nil {
		return
	}

	log.Debugf("start ephemeral peer manager")
	e.loadEphemeralPeers()
	e.startCleanupLoop()
}

// Stop the cleanup loop
func (e *EphemeralManager) Stop() {
	select {
	case e.doneTicker <- struct{}{}:
	default:
	}
}

// OnPeerConnected remove the peer from the list of ephemeral peers. Because of the peer
// is active the system will not delete it while it is active.
func (e *EphemeralManager) OnPeerConnected(peer *Peer) {
	if !peer.Ephemeral {
		return
	}

	e.peersLock.Lock()
	defer e.peersLock.Unlock()
	delete(e.peers, peer.ID)
}

// OnPeerDisconnected add the peer to the list of ephemeral peers. Because of the peer
// is inactive it will be deleted after the timeout period.
func (e *EphemeralManager) OnPeerDisconnected(peer *Peer) {
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

func (e *EphemeralManager) loadEphemeralPeers() {
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

func (e *EphemeralManager) startCleanupLoop() {
	e.uptimeTicker = time.NewTicker(tickerPeriod)
	go func() {
		for {
			select {
			case <-e.uptimeTicker.C:
				e.cleanup()
			case <-e.doneTicker:
				e.uptimeTicker.Stop()
				return
			}
		}
	}()
}

func (e *EphemeralManager) cleanup() {
	now := timeNow()
	deletePeers := make(map[string]prop)

	e.peersLock.Lock()
	for id, p := range e.peers {
		if now.Before(p.deadline) {
			continue
		}

		deletePeers[id] = p
		delete(e.peers, id)
	}
	e.peersLock.Unlock()

	for id, p := range deletePeers {
		log.Debugf("delete ephemeral peer: %s", id)
		// todo: fill with valid user id
		_, err := e.accountManager.DeletePeer(p.account.Id, id, "0")
		if err != nil {
			log.Errorf("failed to delete ephemeral peer: %s", err)
		}
	}
}

func (e *EphemeralManager) addPeer(peerId string, account *Account) {
	e.peersLock.Lock()
	defer e.peersLock.Unlock()

	e.peers[peerId] = prop{
		account,
		newDeadLine(),
	}
}

func newDeadLine() time.Time {
	return timeNow().Add(ephemeralLifeTime)
}
