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

// Events that pile up while the listener is busy are delivered by the final state of
// each peer. A peer that went offline and registered again in the meantime is online,
// so the subscriber must not be told it is offline after being told it is online.
func TestListener_BatchedEventsReportFinalState(t *testing.T) {
	a := messages.HashID("peer-a")
	b := messages.HashID("peer-b")
	c := messages.HashID("peer-c")

	l := newListener(t.Context())
	l.AddInterestedPeers([]messages.PeerID{a, b, c})
	l.peerWentOffline(a)
	l.peerComeOnline(a)
	l.peerComeOnline(b)
	l.peerWentOffline(b)
	l.peerComeOnline(c)

	online := make(chan []messages.PeerID, 1)
	offline := make(chan []messages.PeerID, 1)
	go l.listenForEvents(
		func(ids []messages.PeerID) { online <- ids },
		func(ids []messages.PeerID) { offline <- ids },
	)

	select {
	case ids := <-online:
		assert.ElementsMatch(t, []messages.PeerID{a, c}, ids, "peers whose last event was online")
	case <-time.After(time.Second):
		require.FailNow(t, "missing online notification")
	}
	select {
	case ids := <-offline:
		assert.Equal(t, []messages.PeerID{b}, ids, "peers whose last event was offline")
	case <-time.After(time.Second):
		require.FailNow(t, "missing offline notification")
	}
}
