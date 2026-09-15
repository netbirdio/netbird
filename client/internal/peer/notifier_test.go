package peer

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mocListener struct {
	lastState ClientState
	wg        sync.WaitGroup
	peersWg   sync.WaitGroup
	peers     int
}

func (l *mocListener) OnConnected() {
	l.lastState = ClientStateConnected
	l.wg.Done()
}
func (l *mocListener) OnDisconnected() {
	l.lastState = ClientStateDisconnected
	l.wg.Done()
}
func (l *mocListener) OnConnecting() {
	l.lastState = ClientStateConnecting
	l.wg.Done()
}
func (l *mocListener) OnDisconnecting() {
	l.lastState = ClientStateDisconnecting
	l.wg.Done()
}

func (l *mocListener) OnStateChanged(state ClientState) {

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
		expected    ClientState
		mgmState    bool
		signalState bool
	}
	scenarios := []scenario{
		{"connected", ClientStateConnected, true, true},
		{"mgm down", ClientStateConnecting, false, true},
		{"signal down", ClientStateConnecting, true, false},
		{"disconnected", ClientStateDisconnected, false, false},
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
	n.lastNotification = ClientStateConnecting
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
	n.lastNotification = ClientStateConnecting
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

type coalescingListener struct {
	final       int
	calls       atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	last        atomic.Int32
	done        chan struct{}
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
}

func (l *coalescingListener) OnStateChanged(ClientState)      {}
func (l *coalescingListener) OnConnected()                    {}
func (l *coalescingListener) OnDisconnected()                 {}
func (l *coalescingListener) OnConnecting()                   {}
func (l *coalescingListener) OnDisconnecting()                {}
func (l *coalescingListener) OnAddressChanged(string, string) {}

func (l *coalescingListener) OnPeersListChanged(size int) {
	current := l.inFlight.Add(1)
	for {
		seen := l.maxInFlight.Load()
		if current <= seen || l.maxInFlight.CompareAndSwap(seen, current) {
			break
		}
	}
	if l.calls.Add(1) == 1 && l.entered != nil {
		close(l.entered)
	}
	if l.release != nil {
		<-l.release
	}
	time.Sleep(time.Millisecond)
	l.last.Store(int32(size))
	l.inFlight.Add(-1)
	if size == l.final {
		l.once.Do(func() { close(l.done) })
	}
}

func Test_notifier_PeerListChangedCoalesces(t *testing.T) {
	const events = 1000
	listener := &coalescingListener{final: events, done: make(chan struct{})}
	n := newNotifier()
	n.setListener(listener)

	for i := 1; i <= events; i++ {
		n.peerListChanged(i)
	}

	select {
	case <-listener.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("last peer count not delivered, last seen: %d", listener.last.Load())
	}

	if got := listener.maxInFlight.Load(); got != 1 {
		t.Errorf("concurrent deliveries: %d, expected 1", got)
	}
	if got := listener.calls.Load(); got >= events {
		t.Errorf("deliveries not coalesced: %d calls for %d events", got, events)
	}
}

func Test_notifier_SetListenerStopsPreviousDeliverer(t *testing.T) {
	old := &coalescingListener{
		final:   -1,
		done:    make(chan struct{}),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	replacement := &coalescingListener{final: 7, done: make(chan struct{})}
	n := newNotifier()
	n.setListener(old)
	waitFor(t, old.entered, "old listener not called")

	n.peerListChanged(7)
	n.setListener(replacement)
	close(old.release)

	waitFor(t, replacement.done, "replacement listener not notified")
	time.Sleep(50 * time.Millisecond)

	if got := old.calls.Load(); got != 1 {
		t.Errorf("stale deliverer ran %d times, expected 1", got)
	}
	if got := old.last.Load(); got == 7 {
		t.Errorf("stale deliverer delivered the new peer count")
	}
}

func waitFor(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}
