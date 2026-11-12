package store

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const listenerWaitTimeout = 2 * time.Second

type stalledListener struct {
	notifier *PeerNotifier
	listener *Listener
	release  func()

	mu        sync.Mutex
	delivered map[messages.PeerID][]bool
}

func newStalledListener(t *testing.T) *stalledListener {
	t.Helper()
	blocker := messages.HashID("blocker")
	entered := make(chan struct{})
	release := make(chan struct{})

	s := &stalledListener{
		notifier:  NewPeerNotifier(),
		release:   sync.OnceFunc(func() { close(release) }),
		delivered: make(map[messages.PeerID][]bool),
	}
	s.listener = s.notifier.NewListener(
		func(ids []messages.PeerID) {
			if len(ids) == 1 && ids[0] == blocker {
				close(entered)
				<-release
				return
			}
			s.record(ids, true)
		},
		func(ids []messages.PeerID) {
			s.record(ids, false)
		},
	)
	t.Cleanup(func() {
		s.release()
		s.notifier.RemoveListener(s.listener)
	})

	s.listener.AddInterestedPeers([]messages.PeerID{blocker})
	s.notifier.PeerCameOnline(blocker)
	select {
	case <-entered:
	case <-time.After(listenerWaitTimeout):
		require.Fail(t, "the listener must start delivering the blocker notification")
	}
	return s
}

func (s *stalledListener) record(ids []messages.PeerID, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		s.delivered[id] = append(s.delivered[id], online)
	}
}

func (s *stalledListener) deliveredTo(id messages.PeerID) []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bool(nil), s.delivered[id]...)
}

func (s *stalledListener) publish(id messages.PeerID, online bool) {
	if !online {
		s.notifier.PeerWentOffline(id)
		return
	}
	s.listener.AddInterestedPeers([]messages.PeerID{id})
	s.notifier.PeerCameOnline(id)
}

func (s *stalledListener) waitDelivered(t *testing.T, id messages.PeerID, count int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(s.deliveredTo(id)) >= count
	}, listenerWaitTimeout, time.Millisecond, "the notifications must be delivered")
}

// A sentinel published after the awaited notifications lands in a later round, so
// its delivery proves that every earlier round has been delivered completely.
func (s *stalledListener) waitRoundsDelivered(t *testing.T) {
	t.Helper()
	sentinel := messages.HashID("sentinel")
	s.publish(sentinel, true)
	s.waitDelivered(t, sentinel, 1)
}

func TestListener_KeepsPerPeerOrderWhileStalled(t *testing.T) {
	const online, offline = true, false

	cases := []struct {
		name      string
		published []bool
		want      []bool
	}{
		{"offline then online", []bool{offline, online}, []bool{offline, online}},
		{"online then offline", []bool{online, offline}, []bool{online, offline}},
		{"offline twice", []bool{offline, offline}, []bool{offline}},
		{"offline, online, offline", []bool{offline, online, offline}, []bool{offline}},
		{"online, offline, online", []bool{online, offline, online}, []bool{online}},
		{"four flaps starting offline", []bool{offline, online, offline, online}, []bool{offline, online}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStalledListener(t)
			peerID := messages.HashID("peer")
			s.listener.AddInterestedPeers([]messages.PeerID{peerID})

			for _, state := range tc.published {
				s.publish(peerID, state)
			}
			s.release()

			s.waitDelivered(t, peerID, len(tc.want))
			s.waitRoundsDelivered(t)
			assert.Equal(t, tc.want, s.deliveredTo(peerID), "the peer's notifications must keep their order")
		})
	}
}

func TestListener_PendingStaysBoundedWhileStalled(t *testing.T) {
	s := newStalledListener(t)
	peerID := messages.HashID("peer")

	flapped := make(chan struct{})
	go func() {
		defer close(flapped)
		for range 10000 {
			s.publish(peerID, true)
			s.publish(peerID, false)
		}
	}()
	select {
	case <-flapped:
	case <-time.After(listenerWaitTimeout):
		require.Fail(t, "publishing must not block on a stalled listener")
	}

	s.listener.mu.Lock()
	pending := len(s.listener.pending)
	s.listener.mu.Unlock()
	assert.Equal(t, 1, pending, "a flapping peer must occupy a single pending entry")

	s.release()
	s.waitDelivered(t, peerID, 2)
	s.waitRoundsDelivered(t)
	assert.Equal(t, []bool{true, false}, s.deliveredTo(peerID), "the flaps must collapse to one online and one offline notification")
}

func TestListener_UnsubscribeDropsPending(t *testing.T) {
	s := newStalledListener(t)
	peerID := messages.HashID("peer")

	s.publish(peerID, true)
	s.publish(peerID, false)
	s.listener.RemoveInterestedPeer([]messages.PeerID{peerID})
	s.release()

	s.waitRoundsDelivered(t)
	assert.Empty(t, s.deliveredTo(peerID), "an unsubscribed peer must not be notified")
}

func TestNotifier_RemoveListenerWhileStalled(t *testing.T) {
	s := newStalledListener(t)
	peerID := messages.HashID("peer")
	s.publish(peerID, true)

	removed := make(chan struct{})
	go func() {
		defer close(removed)
		s.notifier.RemoveListener(s.listener)
	}()
	select {
	case <-removed:
	case <-time.After(listenerWaitTimeout):
		require.Fail(t, "a stalled listener must be removable")
	}

	s.release()
	s.notifier.PeerWentOffline(peerID)
	assert.Never(t, func() bool {
		return len(s.deliveredTo(peerID)) > 0
	}, 100*time.Millisecond, 5*time.Millisecond, "a removed listener must not deliver notifications")
}
