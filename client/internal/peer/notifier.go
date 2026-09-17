package peer

import (
	"sync"
)

type notifier struct {
	// publishLock orders state publication: it is held across computing the
	// effective state and handing it to the listener, so a transition cannot
	// overtake a newer one and leave the listener on a stale state.
	publishLock        sync.Mutex
	serverStateLock    sync.Mutex
	listenersLock      sync.Mutex
	listener           Listener
	currentClientState bool
	lastNotification   ClientState
	lastNumberOfPeers  int
	lastFqdnAddress    string
	lastIPAddress      string
	networkAvailable   bool
}

func newNotifier() *notifier {
	return &notifier{
		networkAvailable: true,
	}
}

// effectiveState maps the computed state to what listeners should see:
// while the OS reports no usable network, "Connecting" would be a lie —
// connection attempts are suspended — so it is reported as NoNetwork.
// Caller must hold serverStateLock.
func (n *notifier) effectiveState(state ClientState) ClientState {
	if !n.networkAvailable && state == ClientStateConnecting {
		return ClientStateNoNetwork
	}
	return state
}

// setNetworkAvailable records the OS network availability and re-notifies
// the listener when the flag flips the effective state (Connecting <->
// NoNetwork).
func (n *notifier) setNetworkAvailable(available bool) {
	n.publishLock.Lock()
	defer n.publishLock.Unlock()

	n.serverStateLock.Lock()
	if n.networkAvailable == available {
		n.serverStateLock.Unlock()
		return
	}
	previous := n.effectiveState(n.lastNotification)
	n.networkAvailable = available
	current := n.effectiveState(n.lastNotification)
	n.serverStateLock.Unlock()

	if previous != current {
		n.notify(current)
	}
}

func (n *notifier) setListener(listener Listener) {
	n.serverStateLock.Lock()
	lastNotification := n.effectiveState(n.lastNotification)
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
	n.publishLock.Lock()
	defer n.publishLock.Unlock()

	n.serverStateLock.Lock()
	calculatedState := n.calculateState(mgmState, signalState)

	if !n.isServerStateChanged(calculatedState) {
		n.serverStateLock.Unlock()
		return
	}

	n.lastNotification = calculatedState
	effective := n.effectiveState(calculatedState)
	n.serverStateLock.Unlock()

	n.notify(effective)
}

func (n *notifier) clientStart() {
	n.publishLock.Lock()
	defer n.publishLock.Unlock()

	n.serverStateLock.Lock()
	n.currentClientState = true
	n.lastNotification = ClientStateConnecting
	effective := n.effectiveState(ClientStateConnecting)
	n.serverStateLock.Unlock()

	n.notify(effective)
}

func (n *notifier) clientStop() {
	n.publishLock.Lock()
	defer n.publishLock.Unlock()

	n.serverStateLock.Lock()
	n.currentClientState = false
	n.lastNotification = ClientStateDisconnected
	n.serverStateLock.Unlock()

	n.notify(ClientStateDisconnected)
}

func (n *notifier) clientTearDown() {
	n.publishLock.Lock()
	defer n.publishLock.Unlock()

	n.serverStateLock.Lock()
	n.currentClientState = false
	n.lastNotification = ClientStateDisconnecting
	n.serverStateLock.Unlock()

	n.notify(ClientStateDisconnecting)
}

func (n *notifier) isServerStateChanged(newState ClientState) bool {
	return n.lastNotification != newState
}

func (n *notifier) notify(state ClientState) {
	n.listenersLock.Lock()
	listener := n.listener
	n.listenersLock.Unlock()

	if listener == nil {
		return
	}

	notifyListener(listener, state)
}

func (n *notifier) calculateState(managementConn, signalConn bool) ClientState {
	if managementConn && signalConn {
		return ClientStateConnected
	}

	if !managementConn && !signalConn && !n.currentClientState {
		return ClientStateDisconnected
	}

	if n.lastNotification == ClientStateDisconnecting {
		return ClientStateDisconnecting
	}

	return ClientStateConnecting
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

func notifyListener(l Listener, state ClientState) {
	// legacy per-state callbacks; NoNetwork is delivered only via
	// OnStateChanged below
	switch state {
	case ClientStateDisconnected:
		l.OnDisconnected()
	case ClientStateConnected:
		l.OnConnected()
	case ClientStateConnecting:
		l.OnConnecting()
	case ClientStateDisconnecting:
		l.OnDisconnecting()
	}

	l.OnStateChanged(state)
}
