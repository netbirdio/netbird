package inactivity

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/monotime"
)

// TestTickClosesIdlePeerAfterTenSeconds checks that on mobile an idle link
// closes on the aligned tick after 10 s, in a wake the device has anyway,
// not on the 15 min timer.
func TestTickClosesIdlePeerAfterTenSeconds(t *testing.T) {
	peerID := "peer1"
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{
		peerID: monotime.Time(int64(monotime.Now()) - int64(time.Hour)),
	}}

	tick, subscribe := fakeTickSubscriber(t)

	manager := NewManager(wgMock, nil, subscribe)
	peerLog := log.WithField("peer", peerID)
	manager.AddPeer(&lazyconn.PeerConfig{PublicKey: peerID, Log: peerLog})
	// Eleven seconds after the open, on the manager clock.
	base := monotime.Now()
	manager.now = func() monotime.Time { return base + monotime.Time(11*time.Second) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)
	(<-tick)(time.Minute)
	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, peerID)
	case <-time.After(5 * time.Second):
		t.Fatal("expected the idle peer to close on the tick")
	}
}

// TestTickNeverClosesBeforeTenSecondsAfterOpen covers the open-time floor: the
// interface keeps the last activity across a lazy close, so a just-opened
// link with an old activity stamp must get its full 10 s.
func TestTickNeverClosesBeforeTenSecondsAfterOpen(t *testing.T) {
	peerID := "peer1"
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{
		peerID: monotime.Time(int64(monotime.Now()) - int64(time.Hour)),
	}}

	tick, subscribe := fakeTickSubscriber(t)

	manager := NewManager(wgMock, nil, subscribe)
	peerLog := log.WithField("peer", peerID)
	manager.AddPeer(&lazyconn.PeerConfig{PublicKey: peerID, Log: peerLog})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)
	(<-tick)(time.Minute)
	select {
	case inactivePeers := <-manager.inactivePeersChan:
		t.Fatalf("a fresh link must not close at once, got %v", inactivePeers)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestTimerCheckKeepsStockIdleTime covers the fallback timer on mobile, which
// runs while no aligned tick arrives: it must judge a peer by its last
// activity alone, as stock, so a reopened link with an old activity stamp
// closes on the timer and is not held 15 min past the open.
func TestTimerCheckKeepsStockIdleTime(t *testing.T) {
	peerID := "peer1"
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{
		peerID: monotime.Time(int64(monotime.Now()) - int64(time.Hour)),
	}}

	timer := make(chan time.Time)
	prev := newTicker
	newTicker = func(time.Duration) Ticker { return &fakeTickerMock{CChan: timer} }
	t.Cleanup(func() { newTicker = prev })
	noTicks := func(func(time.Duration)) func() { return func() {} }

	manager := NewManager(wgMock, nil, noTicks)
	manager.AddPeer(&lazyconn.PeerConfig{PublicKey: peerID, Log: log.WithField("peer", peerID)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)
	timer <- time.Now()
	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, peerID, "the timer check uses the last activity alone")
	case <-time.After(5 * time.Second):
		t.Fatal("expected the peer idle for an hour to close on the timer check")
	}
}

// fakeTickSubscriber replaces the timer with one that never fires and returns
// the tick function the manager subscribes, handed over once Start runs.
func fakeTickSubscriber(t *testing.T) (<-chan func(time.Duration), TickSubscriber) {
	t.Helper()
	prev := newTicker
	newTicker = func(time.Duration) Ticker { return &fakeTickerMock{CChan: make(chan time.Time)} }
	t.Cleanup(func() { newTicker = prev })

	tick := make(chan func(time.Duration), 1)
	return tick, func(f func(time.Duration)) func() {
		tick <- f
		return func() {}
	}
}
