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
	lastFqdnAddress    string
	lastIPAddress      string
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener Listener) {
	n.serverStateLock.Lock()
	lastNotification := n.lastNotification
	numOfPeers := n.lastNumberOfPeers
	fqdnAddress := n.lastFqdnAddress
	address := n.lastIPAddress
	n.serverStateLock.Unlock()

	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()

	n.listener = listener

	listener.OnAddressChanged(fqdnAddress, address)
	notifyListener(listener, lastNotification)
	// run on go routine to avoid on Java layer to call go functions on same thread
	go listener.OnPeersListChanged(numOfPeers)
}

func (n *notifier) removeListener() {
	n.listenersLock.Lock()
	defer n.listenersLock.Unlock()
	n.listener = nil
}

func (n *notifier) updateServerStates(mgmState bool, signalState bool) {
	n.serverStateLock.Lock()
	calculatedState := n.calculateState(mgmState, signalState)

	if !n.isServerStateChanged(calculatedState) {
		n.serverStateLock.Unlock()
		return
	}

	n.lastNotification = calculatedState
	n.serverStateLock.Unlock()

	n.notify(calculatedState)
}

func (n *notifier) clientStart() {
	n.serverStateLock.Lock()
	n.currentClientState = true
	n.lastNotification = stateConnecting
	n.serverStateLock.Unlock()

	n.notify(stateConnecting)
}

func (n *notifier) clientStop() {
	n.serverStateLock.Lock()
	n.currentClientState = false
	n.lastNotification = stateDisconnected
	n.serverStateLock.Unlock()

	n.notify(stateDisconnected)
}

func (n *notifier) clientTearDown() {
	n.serverStateLock.Lock()
	n.currentClientState = false
	n.lastNotification = stateDisconnecting
	n.serverStateLock.Unlock()

	n.notify(stateDisconnecting)
}

func (n *notifier) isServerStateChanged(newState int) bool {
	return n.lastNotification != newState
}

func (n *notifier) notify(state int) {
	n.listenersLock.Lock()
	listener := n.listener
	n.listenersLock.Unlock()

	if listener == nil {
		return
	}

	notifyListener(listener, state)
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
	n.serverStateLock.Lock()
	n.lastNumberOfPeers = numOfPeers
	n.serverStateLock.Unlock()

	n.listenersLock.Lock()
	listener := n.listener
	n.listenersLock.Unlock()

	if listener == nil {
		return
	}

	// run on go routine to avoid on Java layer to call go functions on same thread
	go listener.OnPeersListChanged(numOfPeers)
}

func (n *notifier) localAddressChanged(fqdn, address string) {
	n.serverStateLock.Lock()
	n.lastFqdnAddress = fqdn
	n.lastIPAddress = address
	n.serverStateLock.Unlock()

	n.listenersLock.Lock()
	listener := n.listener
	n.listenersLock.Unlock()

	if listener == nil {
		return
	}

	listener.OnAddressChanged(fqdn, address)
}

func notifyListener(l Listener, state int) {
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
}
