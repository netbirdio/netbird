package peer

import (
	"sync"
	"testing"
)

type mocListener struct {
	lastState int
	wg        sync.WaitGroup
	peersWg   sync.WaitGroup
	peers     int
}

func (l *mocListener) OnConnected() {
	l.lastState = stateConnected
	l.wg.Done()
}
func (l *mocListener) OnDisconnected() {
	l.lastState = stateDisconnected
	l.wg.Done()
}
func (l *mocListener) OnConnecting() {
	l.lastState = stateConnecting
	l.wg.Done()
}
func (l *mocListener) OnDisconnecting() {
	l.lastState = stateDisconnecting
	l.wg.Done()
}

func (l *mocListener) OnAddressChanged(host, addr string) {

}
func (l *mocListener) OnPeersListChanged(size int) {
	l.peers = size
	l.peersWg.Done()
}

func (l *mocListener) setWaiter() {
	l.wg.Add(1)
}

func (l *mocListener) wait() {
	l.wg.Wait()
}

func (l *mocListener) setPeersWaiter() {
	l.peersWg.Add(1)
}

func (l *mocListener) waitPeers() {
	l.peersWg.Wait()
}

func Test_notifier_serverState(t *testing.T) {

	type scenario struct {
		name        string
		expected    int
		mgmState    bool
		signalState bool
	}
	scenarios := []scenario{
		{"connected", stateConnected, true, true},
		{"mgm down", stateConnecting, false, true},
		{"signal down", stateConnecting, true, false},
		{"disconnected", stateDisconnected, false, false},
	}

	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			n := newNotifier()
			n.updateServerStates(tt.mgmState, tt.signalState)
			if n.lastNotification != tt.expected {
				t.Errorf("invalid serverstate: %d, expected: %d", n.lastNotification, tt.expected)
			}
		})
	}
}

func Test_notifier_SetListener(t *testing.T) {
	listener := &mocListener{}
	listener.setWaiter()
	listener.setPeersWaiter()

	n := newNotifier()
	n.lastNotification = stateConnecting
	n.setListener(listener)
	listener.wait()
	listener.waitPeers()
	if listener.lastState != n.lastNotification {
		t.Errorf("invalid state: %d, expected: %d", listener.lastState, n.lastNotification)
	}
}

func Test_notifier_RemoveListener(t *testing.T) {
	listener := &mocListener{}
	listener.setWaiter()
	listener.setPeersWaiter()
	n := newNotifier()
	n.lastNotification = stateConnecting
	n.setListener(listener)
	// setListener replays cached state on a goroutine; wait for both the state
	// and peers callbacks to finish so we don't race on listener.peers.
	listener.wait()
	listener.waitPeers()
	n.removeListener()
	n.peerListChanged(1)

	if listener.peers != 0 {
		t.Errorf("invalid state: %d", listener.peers)
	}
}
