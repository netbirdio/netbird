package server

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const notificationBurstSize = 300

type onlineWriteGate struct {
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
}

func (g *onlineWriteGate) arm(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})

	g.mu.Lock()
	g.entered, g.release = entered, release
	g.mu.Unlock()

	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	return entered, releaseOnce
}

func (g *onlineWriteGate) onWrite(frame []byte) {
	if frame[1] != byte(messages.MsgTypePeersOnline) {
		return
	}

	g.mu.Lock()
	entered, release := g.entered, g.release
	g.entered, g.release = nil, nil
	g.mu.Unlock()

	if release == nil {
		return
	}
	close(entered)
	<-release
}

func TestPeer_StalledSubscriberDoesNotBlockPeerLifecycle(t *testing.T) {
	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		// Shutdown needs the store lock, so it would hang forever behind a lock cycle
		// this test has just reported.
		if t.Failed() {
			return
		}
		relay.Shutdown(context.Background())
	})

	anchor := publishOnline(relay, "anchor")
	firstID := messages.HashID("first")
	secondID := messages.HashID("second")
	burstIDs := make([]messages.PeerID, 0, notificationBurstSize)
	for i := range notificationBurstSize {
		burstIDs = append(burstIDs, messages.HashID(fmt.Sprintf("burst-%d", i)))
	}

	gate := &onlineWriteGate{}
	subscriberID := messages.HashID("subscriber")
	subscriberConn := newScriptedConn()
	subscriberConn.onWrite = gate.onWrite
	auth, err := messages.MarshalAuthMsg(subscriberID, []byte("token"))
	require.NoError(t, err)
	subscriberConn.deliver(t, auth)
	relay.Accept(subscriberConn)
	subscriberConn.waitFrames(t, 1)

	// The anchor is the only online peer and comes last, so its answer proves that
	// every subscription frame has been registered.
	watched := append([]messages.PeerID{firstID, secondID}, burstIDs...)
	watched = append(watched, anchor.ID())
	deliverSubscription(t, subscriberConn, watched)
	subscriberConn.waitFrames(t, 2)
	stored, ok := relay.store.Peer(subscriberID)
	require.True(t, ok, "the subscriber must be in the store")
	subscriberListener := stored.(*Peer).peersListener

	firstWriteEntered, releaseFirstWrite := gate.arm(t)
	publishOnline(relay, "first")
	requireCompletes(t, firstWriteEntered, "the first online notification must reach the subscriber connection")

	publishOnline(relay, "second")
	publishOffline(relay, anchor)

	// The listener now stalls in the online write while it already holds the
	// anchor's offline event, without holding the notification mutex.
	secondWriteEntered, releaseSecondWrite := gate.arm(t)
	releaseFirstWrite()
	requireCompletes(t, secondWriteEntered, "the second online notification must reach the subscriber connection")

	burstDone := make(chan struct{})
	go func() {
		defer close(burstDone)
		for i := range notificationBurstSize {
			publishOnline(relay, fmt.Sprintf("burst-%d", i))
		}
	}()
	assertCompletes(t, burstDone, "a stalled subscriber must not block peers that come online")

	deliverSubscription(t, subscriberConn, []messages.PeerID{firstID})
	assert.Eventually(t, func() bool {
		return len(subscriberConn.frames()) >= 5
	}, testWaitTimeout, 5*time.Millisecond, "a subscription must be answered while the listener is stalled")

	releaseSecondWrite()

	bystanderDone := make(chan struct{})
	go func() {
		defer close(bystanderDone)
		publishOffline(relay, publishOnline(relay, "bystander"))
	}()
	assertCompletes(t, bystanderDone, "an unrelated peer must be able to join and leave")

	wantOnline := append([]messages.PeerID{firstID, firstID, secondID}, burstIDs...)
	assert.Eventually(t, func() bool {
		online, _, err := decodeNotifications(subscriberConn.frames()[2:])
		return err == nil && len(online) >= len(wantOnline)
	}, testWaitTimeout, 5*time.Millisecond, "every online notification must be delivered")
	online, offline, err := decodeNotifications(subscriberConn.frames()[2:])
	require.NoError(t, err)
	assert.ElementsMatch(t, wantOnline, online, "each online notification must be delivered exactly once")
	assert.Equal(t, []messages.PeerID{anchor.ID()}, offline, "the offline notification must be delivered exactly once")

	removeDone := make(chan struct{})
	go func() {
		defer close(removeDone)
		relay.notifier.RemoveListener(subscriberListener)
	}()
	assertCompletes(t, removeDone, "the subscriber's listener must be removable")

	require.NoError(t, subscriberConn.Close())
	assert.Eventually(t, func() bool {
		_, ok := relay.store.Peer(subscriberID)
		return !ok
	}, testWaitTimeout, 5*time.Millisecond, "the disconnected subscriber must be removed from the store")
}

func publishOnline(relay *Relay, name string) *Peer {
	peer := NewPeer(relay.metrics, messages.HashID(name), messages.CurrentProtocolVersion, newScriptedConn(), relay.store, relay.notifier)
	relay.store.AddPeer(peer)
	relay.notifier.PeerCameOnline(peer.ID())
	return peer
}

func publishOffline(relay *Relay, peer *Peer) {
	if relay.store.DeletePeer(peer) {
		relay.notifier.PeerWentOffline(peer.ID())
	}
	peer.Close()
}

func deliverSubscription(t *testing.T, conn *scriptedConn, ids []messages.PeerID) {
	t.Helper()
	frames, err := messages.MarshalSubPeerStateMsg(ids)
	require.NoError(t, err)
	for _, frame := range frames {
		conn.deliver(t, frame)
	}
}

func decodeNotifications(frames [][]byte) (online, offline []messages.PeerID, err error) {
	for _, frame := range frames {
		switch messages.MsgType(frame[1]) {
		case messages.MsgTypePeersOnline:
			ids, err := messages.UnmarshalPeersOnlineMsg(frame)
			if err != nil {
				return nil, nil, err
			}
			online = append(online, ids...)
		case messages.MsgTypePeersWentOffline:
			ids, err := messages.UnMarshalPeersWentOffline(frame)
			if err != nil {
				return nil, nil, err
			}
			offline = append(offline, ids...)
		}
	}
	return online, offline, nil
}

func requireCompletes(t *testing.T, done <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testWaitTimeout):
		require.Fail(t, msg)
	}
}

func assertCompletes(t *testing.T, done <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testWaitTimeout):
		assert.Fail(t, msg)
	}
}
