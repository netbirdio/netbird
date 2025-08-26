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

type mockWgInterface struct {
	lastActivities map[string]monotime.Time
}

func (m *mockWgInterface) LastActivities() map[string]monotime.Time {
	return m.lastActivities
}

func TestPeerTriggersInactivity(t *testing.T) {
	peerID := "peer1"

	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: monotime.Time(int64(monotime.Now()) - int64(20*time.Minute)),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	peerLog := log.WithField("peer", peerID)
	peerCfg := &lazyconn.PeerConfig{
		PublicKey: peerID,
		Log:       peerLog,
	}

	manager := NewManager(wgMock, nil)
	manager.AddPeer(peerCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the manager in a goroutine
	go manager.Start(ctx)

	// Send a tick to simulate time passage
	fakeTick <- time.Now()

	// Check if peer appears on inactivePeersChan
	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, peerID, "expected peer to be marked inactive")
	case <-time.After(1 * time.Second):
		t.Fatal("expected inactivity event, but none received")
	}
}

func TestPeerTriggersActivity(t *testing.T) {
	peerID := "peer1"

	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: monotime.Time(int64(monotime.Now()) - int64(5*time.Minute)),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	peerLog := log.WithField("peer", peerID)
	peerCfg := &lazyconn.PeerConfig{
		PublicKey: peerID,
		Log:       peerLog,
	}

	manager := NewManager(wgMock, nil)
	manager.AddPeer(peerCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the manager in a goroutine
	go manager.Start(ctx)

	// Send a tick to simulate time passage
	fakeTick <- time.Now()

	// Check if peer appears on inactivePeersChan
	select {
	case <-manager.inactivePeersChan:
		t.Fatal("expected inactive peer to be marked inactive")
	case <-time.After(1 * time.Second):
		// No inactivity event should be received
	}
}

// fakeTickerMock implements Ticker interface for testing
type fakeTickerMock struct {
	CChan chan time.Time
}

func (f *fakeTickerMock) C() <-chan time.Time {
	return f.CChan
}

func (f *fakeTickerMock) Stop() {}
