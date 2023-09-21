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
	currentClientState bool
	lastNotification   int
	lastNumberOfPeers  int
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener Listener) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()

	n.serverStateLock.Lock()
	n.notifyListener(listener, n.lastNotification)
	listener.OnPeersListChanged(n.lastNumberOfPeers)
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

	calculatedState := n.calculateState(mgmState, signalState)

	if !n.isServerStateChanged(calculatedState) {
		return
	}

	n.lastNotification = calculatedState

	n.notify(n.lastNotification)
}

func (n *notifier) clientStart() {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()
	n.currentClientState = true
	n.lastNotification = stateConnecting
	n.notify(n.lastNotification)
}

func (n *notifier) clientStop() {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()
	n.currentClientState = false
	n.lastNotification = stateDisconnected
	n.notify(n.lastNotification)
}

func (n *notifier) clientTearDown() {
	n.serverStateLock.Lock()
	defer n.serverStateLock.Unlock()
	n.currentClientState = false
	n.lastNotification = stateDisconnecting
	n.notify(n.lastNotification)
}

func (n *notifier) isServerStateChanged(newState int) bool {
	return n.lastNotification != newState
}

func (n *notifier) notify(state int) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	if n.listener == nil {
		return
	}
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

func (n *notifier) calculateState(managementConn, signalConn bool) int {
	if managementConn && signalConn {
		return stateConnected
	}

	if !managementConn && !signalConn && !n.currentClientState {
		return stateDisconnected
	}

	if n.lastNotification == stateDisconnecting {
		return stateDisconnecting
	}

	return stateConnecting
}

func (n *notifier) peerListChanged(numOfPeers int) {
	n.lastNumberOfPeers = numOfPeers
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	if n.listener == nil {
		return
	}
	n.listener.OnPeersListChanged(numOfPeers)
}

func (n *notifier) localAddressChanged(fqdn, address string) {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	if n.listener == nil {
		return
	}
	n.listener.OnAddressChanged(fqdn, address)
}
