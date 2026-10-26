package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// A subscriber must hear about every registration of a peer it is interested in,
// not only the first one. After a silent network loss the peer re-registers with
// the same ID and the replaced registration emits no offline event, so the online
// notification is the only signal the subscriber gets.
func TestListener_OnlineNotifiedOnEveryRegistration(t *testing.T) {
	online := make(chan []messages.PeerID, 4)
	notifier := NewPeerNotifier()
	listener := notifier.NewListener(func(ids []messages.PeerID) { online <- ids }, func([]messages.PeerID) {})
	t.Cleanup(func() { notifier.RemoveListener(listener) })

	peerID := messages.HashID("peer-a")
	listener.AddInterestedPeers([]messages.PeerID{peerID})

	for i := 0; i < 2; i++ {
		notifier.PeerCameOnline(peerID)

		select {
		case ids := <-online:
			assert.Equal(t, []messages.PeerID{peerID}, ids, "registration %d", i+1)
		case <-time.After(time.Second):
			require.FailNowf(t, "missing online notification", "registration %d was not notified", i+1)
		}
	}
}

func TestListener_NoOnlineAfterInterestRemoved(t *testing.T) {
	online := make(chan []messages.PeerID, 1)
	notifier := NewPeerNotifier()
	listener := notifier.NewListener(func(ids []messages.PeerID) { online <- ids }, func([]messages.PeerID) {})
	t.Cleanup(func() { notifier.RemoveListener(listener) })

	peerID := messages.HashID("peer-a")
	listener.AddInterestedPeers([]messages.PeerID{peerID})
	listener.RemoveInterestedPeer([]messages.PeerID{peerID})

	notifier.PeerCameOnline(peerID)

	select {
	case ids := <-online:
		require.FailNowf(t, "unexpected notification", "got online for %v after unsubscribe", ids)
	case <-time.After(100 * time.Millisecond):
	}
}

// Events that pile up while the listener is busy are delivered in the order they
// happened. A peer that went offline and registered again in the meantime must be
// reported offline first: clients that only act on the offline event tear down the
// relayed connection of the previous registration, and the online event that follows
// must not be followed by an offline one for the same registration.
func TestListener_BatchedEventsKeepOrder(t *testing.T) {
	a := messages.HashID("peer-a")
	b := messages.HashID("peer-b")
	c := messages.HashID("peer-c")

	l := newListener(t.Context())
	l.AddInterestedPeers([]messages.PeerID{a, b, c})
	l.peerWentOffline(a)
	l.peerComeOnline(a)
	l.peerComeOnline(b)
	l.peerComeOnline(b)
	l.peerWentOffline(b)
	l.peerComeOnline(c)

	type notification struct {
		online bool
		ids    []messages.PeerID
	}
	notifications := make(chan notification, 8)
	go l.listenForEvents(
		func(ids []messages.PeerID) { notifications <- notification{online: true, ids: ids} },
		func(ids []messages.PeerID) { notifications <- notification{online: false, ids: ids} },
	)

	want := []notification{
		{online: false, ids: []messages.PeerID{a}},
		{online: true, ids: []messages.PeerID{a, b}},
		{online: false, ids: []messages.PeerID{b}},
		{online: true, ids: []messages.PeerID{c}},
	}
	for i, w := range want {
		select {
		case got := <-notifications:
			assert.Equal(t, w, got, "notification %d", i)
		case <-time.After(time.Second):
			require.FailNowf(t, "missing notification", "notification %d", i)
		}
	}
}
