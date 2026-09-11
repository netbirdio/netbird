package peer

import (
	"sync"
	"testing"
	"time"
)

type recordingListener struct {
	mu      sync.Mutex
	states  []ClientState
	onState func(ClientState)
}

func (l *recordingListener) OnStateChanged(state ClientState) {
	l.mu.Lock()
	l.states = append(l.states, state)
	hook := l.onState
	l.mu.Unlock()

	if hook != nil {
		hook(state)
	}
}

func (l *recordingListener) last() (ClientState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.states) == 0 {
		return 0, false
	}
	return l.states[len(l.states)-1], true
}

func (l *recordingListener) snapshot() []ClientState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ClientState(nil), l.states...)
}

func (l *recordingListener) OnConnected()                    {}
func (l *recordingListener) OnDisconnected()                 {}
func (l *recordingListener) OnConnecting()                   {}
func (l *recordingListener) OnDisconnecting()                {}
func (l *recordingListener) OnAddressChanged(string, string) {}
func (l *recordingListener) OnPeersListChanged(int)          {}

// TestNotifier_ConcurrentAvailabilityFlipOrdersPublication holds the first
// transition inside the listener callback and flips availability again from
// another goroutine while it is parked. The second flip must not publish
// ahead of the one in flight, otherwise the listener ends up on a state the
// notifier already superseded.
func TestNotifier_ConcurrentAvailabilityFlipOrdersPublication(t *testing.T) {
	n := newNotifier()
	n.currentClientState = true
	n.lastNotification = ClientStateConnecting

	entered := make(chan struct{})
	release := make(chan struct{})

	l := &recordingListener{}
	l.onState = func(state ClientState) {
		if state != ClientStateNoNetwork {
			return
		}
		l.mu.Lock()
		l.onState = nil
		l.mu.Unlock()
		close(entered)
		<-release
	}
	n.listener = l

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.setNetworkAvailable(false)
	}()

	<-entered

	flipped := make(chan struct{})
	go func() {
		defer close(flipped)
		n.setNetworkAvailable(true)
	}()

	select {
	case <-flipped:
		t.Fatal("the online transition published while the offline one was " +
			"still in flight; publication is not serialized")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	<-flipped
	wg.Wait()

	got, ok := l.last()
	if !ok {
		t.Fatal("listener never observed a state")
	}
	if got != ClientStateConnecting {
		t.Fatalf("listener holds %v after the network came back, want Connecting; sequence: %v",
			got, l.snapshot())
	}
}
