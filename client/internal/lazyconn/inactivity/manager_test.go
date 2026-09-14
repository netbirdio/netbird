package inactivity

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
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

func TestConcurrentPeerAccess(t *testing.T) {
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{}}
	mgr := NewManager(wgMock, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// stands in for the ticker goroutine started by Start
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if _, err := mgr.checkStats(); err != nil {
					t.Errorf("checkStats: %v", err)
					return
				}
			}
		}
	}()

	// stands in for the engine and the inactivity callbacks
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				key := fmt.Sprintf("peer-%d-%d", worker, j%16)
				mgr.AddPeer(&lazyconn.PeerConfig{
					PublicKey: key,
					Log:       log.WithField("peer", key),
				})
				mgr.RemovePeer(key)
			}
		}(i)
	}

	time.Sleep(200 * time.Millisecond)
	cancel()
	wg.Wait()
}

// idleWg reports the peer as idle for long enough to trip the threshold.
func idleWg(peerID string) *mockWgInterface {
	return &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: monotime.Time(int64(monotime.Now()) - int64(20*time.Minute)),
		},
	}
}

func connIDOf(anchor *int) peerid.ConnID {
	return peerid.ConnID(unsafe.Pointer(anchor))
}

// A peer can be removed and re-added between the inactivity check and the moment
// the consumer reads the event. The re-added peer is a different connection, so
// the event has to say which connection it was found idle on; otherwise the
// consumer cannot tell a stale signal from a live one and tears down a
// connection that has just been established.
func TestInactivityEventNamesTheConnectionItWasFoundOn(t *testing.T) {
	peerID := "peer1"
	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	var anchor int
	connID := connIDOf(&anchor)

	manager := NewManager(idleWg(peerID), nil)
	manager.AddPeer(&lazyconn.PeerConfig{
		PublicKey:  peerID,
		PeerConnID: connID,
		Log:        log.WithField("peer", peerID),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)
	fakeTick <- time.Now()

	select {
	case inactive := <-manager.inactivePeersChan:
		got, ok := inactive[peerID]
		assert.True(t, ok, "expected the peer to be reported inactive")
		assert.Equal(t, connID, got, "the event must carry the connection the peer was idle on")
	case <-time.After(time.Second):
		t.Fatal("expected inactivity event, but none received")
	}
}

// After a peer is removed and re-added it is a new connection, and the manager
// must report that one -- reporting the old connection is what lets a stale
// event land on the new one.
func TestReAddedPeerIsReportedOnItsNewConnection(t *testing.T) {
	peerID := "peer1"
	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	var oldAnchor, newAnchor int
	oldConn, newConn := connIDOf(&oldAnchor), connIDOf(&newAnchor)

	manager := NewManager(idleWg(peerID), nil)
	manager.AddPeer(&lazyconn.PeerConfig{PublicKey: peerID, PeerConnID: oldConn, Log: log.WithField("peer", peerID)})
	manager.RemovePeer(peerID)
	manager.AddPeer(&lazyconn.PeerConfig{PublicKey: peerID, PeerConnID: newConn, Log: log.WithField("peer", peerID)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)
	fakeTick <- time.Now()

	select {
	case inactive := <-manager.inactivePeersChan:
		assert.Equal(t, newConn, inactive[peerID], "the event must name the live connection, not the replaced one")
		assert.NotEqual(t, oldConn, inactive[peerID])
	case <-time.After(time.Second):
		t.Fatal("expected inactivity event, but none received")
	}
}
