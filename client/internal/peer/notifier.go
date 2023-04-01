package peer

import (
	"sync"
)

const (
	stateDisconnected = iota
	stateConnected
	stateConnecting
	stateDisconnecting
)

type notifier struct {
	serverStateLock    sync.Mutex
	listenersLock      sync.Mutex
	listener           Listener
	currentServerState bool
	currentClientState bool
	lastNotification   int
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener Listener) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()

	n.serverStateLock.Lock()
	n.notifyListener(listener, n.lastNotification)
	n.serverStateLock.Unlock()

	n.listener = listener
}

func (n *notifier) removeListener() {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	n.listener = nil
}

func (n *notifier) updateServerStates(mgmState bool, signalState bool) {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()

	var newState bool
	if mgmState && signalState {
		newState = true
	} else {
		newState = false
	}

	if !n.isServerStateChanged(newState) {
		return
	}

	n.currentServerState = newState

	if n.lastNotification == stateDisconnecting {
		return
	}

	n.lastNotification = n.calculateState(newState, n.currentClientState)
	n.notify(n.lastNotification)
}

func (n *notifier) clientStart() {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()
	n.currentClientState = true
	n.lastNotification = n.calculateState(n.currentServerState, true)
	n.notify(n.lastNotification)
}

func (n *notifier) clientStop() {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()
	n.currentClientState = false
	n.lastNotification = n.calculateState(n.currentServerState, false)
	n.notify(n.lastNotification)
}

func (n *notifier) clientTearDown() {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()
	n.currentClientState = false
	n.lastNotification = stateDisconnecting
	n.notify(n.lastNotification)
}

func (n *notifier) isServerStateChanged(newState bool) bool {
	return n.currentServerState != newState
}

func (n *notifier) notify(state int) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()

	n.notifyListener(n.listener, state)
}

func (n *notifier) notifyListener(l Listener, state int) {
	go func() {
		switch state {
		case stateDisconnected:
			l.OnDisconnected()
		case stateConnected:
			l.OnConnected()
		case stateConnecting:
			l.OnConnecting()
		case stateDisconnecting:
			l.OnDisconnecting()
		}
	}()
}

func (n *notifier) calculateState(serverState bool, clientState bool) int {
	if serverState && clientState {
		return stateConnected
	}

	if !clientState {
		return stateDisconnected
	}

	return stateConnecting
}

func (n *notifier) peerListChanged(numOfPeers int) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	n.listener.OnPeersListChanged(numOfPeers)
}

func (n *notifier) localAddressChanged(fqdn, address string) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	n.listener.OnAddressChanged(fqdn, address)
}
