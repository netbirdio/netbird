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
	timeNow = time.Now
)

type ephemeralPeer struct {
	id       string
	account  *Account
	deadline time.Time
	next     *ephemeralPeer
}

// todo: consider to remove peer from ephemeral list when the peer has been deleted via API

// EphemeralManager keep a list of ephemeral peers. After ephemeralLifeTime inactivity the peer will be deleted
// automatically. Inactivity means the peer disconnected from the Management server.
type EphemeralManager struct {
	store          Store
	accountManager AccountManager

	headPeer  *ephemeralPeer
	tailPeer  *ephemeralPeer
	peersLock sync.Mutex
	timer     *time.Timer
}

// NewEphemeralManager instantiate new EphemeralManager
func NewEphemeralManager(store Store, accountManager AccountManager) *EphemeralManager {
	return &EphemeralManager{
		store:          store,
		accountManager: accountManager,
	}
}

// Start the ephemeral cleanup loop. Periodically check the list of inactive peers.
// After the peer reach the timeout period it will be deleted from the system.
func (e *EphemeralManager) Start() {
	log.Debugf("start ephemeral peer manager")
	e.peersLock.Lock()
	defer e.peersLock.Unlock()

	e.loadEphemeralPeers()
	if e.headPeer != nil {
		e.timer = time.AfterFunc(ephemeralLifeTime, e.cleanup)
	}
}

// Stop the cleanup loop
func (e *EphemeralManager) Stop() {
	e.peersLock.Lock()
	defer e.peersLock.Unlock()

	if e.timer != nil {
		e.timer.Stop()
	}
}

// OnPeerConnected remove the peer from the linked list of ephemeral peers. Because of the peer
// is active the system will not delete it while it is active.
func (e *EphemeralManager) OnPeerConnected(peer *Peer) {
	if !peer.Ephemeral {
		return
	}

	e.peersLock.Lock()
	defer e.peersLock.Unlock()

	e.removePeer(peer.ID)
}

// OnPeerDisconnected add the peer to the linked list of ephemeral peers. Because of the peer
// is inactive it will be deleted after the ephemeralLifeTime period.
func (e *EphemeralManager) OnPeerDisconnected(peer *Peer) {
	if !peer.Ephemeral {
		return
	}

	a, err := e.store.GetAccountByPeerID(peer.ID)
	if err != nil {
		log.Errorf("failed to add peer to ephemeral list: %s", err)
		return
	}

	e.peersLock.Lock()
	defer e.peersLock.Unlock()

	e.addPeer(peer.ID, a, newDeadLine())
	if e.timer == nil {
		e.timer = time.AfterFunc(e.headPeer.deadline.Sub(timeNow()), e.cleanup)
	}
}

func (e *EphemeralManager) loadEphemeralPeers() {
	accounts := e.store.GetAllAccounts()
	t := newDeadLine()
	count := 0
	for _, a := range accounts {
		for id, p := range a.Peers {
			if p.Ephemeral {
				count++
				e.addPeer(id, a, t)
			}
		}
	}
	log.Debugf("loaded %d ephemeral peers", count)
}

func (e *EphemeralManager) cleanup() {
	deletePeers := make(map[string]*ephemeralPeer)

	e.peersLock.Lock()
	now := timeNow()
	for p := e.headPeer; p != nil; p = p.next {
		if now.Before(p.deadline) {
			break
		}

		deletePeers[p.id] = p
		e.headPeer = p.next
		if e.headPeer == nil {
			e.tailPeer = nil
		}
	}

	if e.headPeer != nil {
		e.timer = time.AfterFunc(e.headPeer.deadline.Sub(timeNow()), e.cleanup)
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

func (e *EphemeralManager) addPeer(id string, account *Account, deadline time.Time) {
	ep := &ephemeralPeer{
		id:       id,
		account:  account,
		deadline: deadline,
	}

	if e.headPeer == nil {
		e.headPeer = ep
	}
	if e.tailPeer != nil {
		e.tailPeer.next = ep
	}
	e.tailPeer = ep
}

func (e *EphemeralManager) removePeer(id string) {
	if e.headPeer == nil {
		return
	}

	if e.headPeer.id == id {
		e.headPeer = e.headPeer.next
		return
	}

	for p := e.headPeer; p.next != nil; p = p.next {
		if p.next == nil {
			return
		}

		if p.next.id == id {
			p.next = p.next.next
		}
	}
}

func newDeadLine() time.Time {
	return timeNow().Add(ephemeralLifeTime)
}
