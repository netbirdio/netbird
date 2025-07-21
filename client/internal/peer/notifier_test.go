package peer

import (
	"sync"
	"testing"
)

type mocListener struct {
	lastState int
	wg        sync.WaitGroup
	peers     int
	mux       sync.Mutex
}

func (l *mocListener) OnConnected() {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.lastState = stateConnected
	l.wg.Done()
}
func (l *mocListener) OnDisconnected() {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.lastState = stateDisconnected
	l.wg.Done()
}
func (l *mocListener) OnConnecting() {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.lastState = stateConnecting
	l.wg.Done()
}
func (l *mocListener) OnDisconnecting() {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.lastState = stateDisconnecting
	l.wg.Done()

}

func (l *mocListener) getLastState() int {
	l.mux.Lock()
	defer l.mux.Unlock()
	return l.lastState
}

func (l *mocListener) OnAddressChanged(host, addr string) {

}
func (l *mocListener) OnPeersListChanged(size int) {
	l.mux.Lock()
	l.peers = size
	l.mux.Unlock()
}

func (l *mocListener) getPeers() int {
	l.mux.Lock()
	defer l.mux.Unlock()
	return l.peers
}

func (l *mocListener) setWaiter() {
	l.wg.Add(1)
}

func (l *mocListener) wait() {
	l.wg.Wait()
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

	n := newNotifier()
	n.lastNotification = stateConnecting
	n.setListener(listener)
	listener.wait()
	if listener.getLastState() != n.lastNotification {
		t.Errorf("invalid state: %d, expected: %d", listener.lastState, n.lastNotification)
	}
}

func Test_notifier_RemoveListener(t *testing.T) {
	listener := &mocListener{}
	listener.setWaiter()
	n := newNotifier()
	n.lastNotification = stateConnecting
	n.setListener(listener)
	n.removeListener()
	n.peerListChanged(1)

	if listener.getPeers() != 0 {
		t.Errorf("invalid state: %d", listener.peers)
	}
}
