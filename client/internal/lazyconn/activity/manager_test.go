package activity

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

type MocPeer struct {
	PeerID string
}

func (m *MocPeer) ConnID() peerid.ConnID {
	return peerid.ConnID(m)
}

type MocWGIface struct {
}

func (m MocWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	return nil
}

func (m MocWGIface) IsUserspaceBind() bool {
	return false
}

func (m MocWGIface) Address() wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/16"),
	}
}

func (m MocWGIface) MTU() uint16 {
	return 1280
}

// GetPeerListener is a test helper to access listeners
func (m *Manager) GetPeerListener(peerConnID peerid.ConnID) (listener, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, exists := m.peers[peerConnID]
	return l, exists
}

func TestManager_MonitorPeerActivity(t *testing.T) {
	mocWgInterface := &MocWGIface{}

	peer1 := &MocPeer{
		PeerID: "examplePublicKey1",
	}
	mgr := NewManager(mocWgInterface)
	defer mgr.Close()
	peerCfg1 := lazyconn.PeerConfig{
		PublicKey:  peer1.PeerID,
		PeerConnID: peer1.ConnID(),
		Log:        log.WithField("peer", "examplePublicKey1"),
	}

	if err := mgr.MonitorPeerActivity(peerCfg1); err != nil {
		t.Fatalf("failed to monitor peer activity: %v", err)
	}

	listener, exists := mgr.GetPeerListener(peerCfg1.PeerConnID)
	if !exists {
		t.Fatalf("peer listener not found")
	}

	// Get the UDP listener's address for triggering
	udpListener, ok := listener.(*UDPListener)
	if !ok {
		t.Fatalf("expected UDPListener")
	}
	if err := trigger(udpListener.conn.LocalAddr().String()); err != nil {
		t.Fatalf("failed to trigger activity: %v", err)
	}

	select {
	case ev := <-mgr.OnActivityChan:
		if ev.PeerConnID != peerCfg1.PeerConnID {
			t.Fatalf("unexpected peerConnID: %v", ev.PeerConnID)
		}
		if !bytes.Equal(ev.FirstPacket, []byte{0x01, 0x02, 0x03, 0x04, 0x05}) {
			t.Fatalf("unexpected first packet: %v", ev.FirstPacket)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for activity")
	}
}

func TestManager_RemovePeerActivity(t *testing.T) {
	mocWgInterface := &MocWGIface{}

	peer1 := &MocPeer{
		PeerID: "examplePublicKey1",
	}
	mgr := NewManager(mocWgInterface)
	defer mgr.Close()

	peerCfg1 := lazyconn.PeerConfig{
		PublicKey:  peer1.PeerID,
		PeerConnID: peer1.ConnID(),
		Log:        log.WithField("peer", "examplePublicKey1"),
	}

	if err := mgr.MonitorPeerActivity(peerCfg1); err != nil {
		t.Fatalf("failed to monitor peer activity: %v", err)
	}

	listener, _ := mgr.GetPeerListener(peerCfg1.PeerConnID)
	udpListener, _ := listener.(*UDPListener)
	addr := udpListener.conn.LocalAddr().String()

	mgr.RemovePeer(peerCfg1.Log, peerCfg1.PeerConnID)

	if err := trigger(addr); err != nil {
		t.Fatalf("failed to trigger activity: %v", err)
	}

	select {
	case <-mgr.OnActivityChan:
		t.Fatal("should not have active activity")
	case <-time.After(1 * time.Second):
	}
}

func TestManager_MultiPeerActivity(t *testing.T) {
	mocWgInterface := &MocWGIface{}

	peer1 := &MocPeer{
		PeerID: "examplePublicKey1",
	}
	mgr := NewManager(mocWgInterface)
	defer mgr.Close()

	peerCfg1 := lazyconn.PeerConfig{
		PublicKey:  peer1.PeerID,
		PeerConnID: peer1.ConnID(),
		Log:        log.WithField("peer", "examplePublicKey1"),
	}

	peer2 := &MocPeer{}
	peerCfg2 := lazyconn.PeerConfig{
		PublicKey:  peer2.PeerID,
		PeerConnID: peer2.ConnID(),
		Log:        log.WithField("peer", "examplePublicKey2"),
	}

	if err := mgr.MonitorPeerActivity(peerCfg1); err != nil {
		t.Fatalf("failed to monitor peer activity: %v", err)
	}

	if err := mgr.MonitorPeerActivity(peerCfg2); err != nil {
		t.Fatalf("failed to monitor peer activity: %v", err)
	}

	listener, exists := mgr.GetPeerListener(peerCfg1.PeerConnID)
	if !exists {
		t.Fatalf("peer listener for peer1 not found")
	}

	udpListener1, _ := listener.(*UDPListener)
	if err := trigger(udpListener1.conn.LocalAddr().String()); err != nil {
		t.Fatalf("failed to trigger activity: %v", err)
	}

	listener, exists = mgr.GetPeerListener(peerCfg2.PeerConnID)
	if !exists {
		t.Fatalf("peer listener for peer2 not found")
	}

	udpListener2, _ := listener.(*UDPListener)
	if err := trigger(udpListener2.conn.LocalAddr().String()); err != nil {
		t.Fatalf("failed to trigger activity: %v", err)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-mgr.OnActivityChan:
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for activity")
		}
	}
}

// fakeChurnListener implements the listener interface with channel gates to
// deterministically hold open the window between ReadPackets returning and
// waitForTraffic acquiring m.mu (no sleeps).
type fakeChurnListener struct {
	released chan struct{}  // closed by Close() (or by the test to simulate traffic)
	proceed  chan struct{}  // test gate: ReadPackets returns only after this is closed
	result   ActivityResult // reason ReadPackets reports (zero value = Closed)
	captured []byte
}

func newFakeChurnListener() *fakeChurnListener {
	return &fakeChurnListener{
		released: make(chan struct{}),
		proceed:  make(chan struct{}),
	}
}

func (f *fakeChurnListener) ReadPackets() ActivityResult {
	<-f.released
	<-f.proceed
	return f.result
}

func (f *fakeChurnListener) Close() {
	select {
	case <-f.released:
	default:
		close(f.released)
	}
}

func (f *fakeChurnListener) CapturedPacket() []byte { return f.captured }

// armListener mirrors MonitorPeerActivity for injected fake listeners:
// register under m.mu, then start waitForTraffic. Returns a channel that is
// closed when the goroutine finishes.
func (m *Manager) armListener(connID peerid.ConnID, l listener) chan struct{} {
	m.mu.Lock()
	m.peers[connID] = l
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.waitForTraffic(l, connID)
		close(done)
	}()
	return done
}

// TestManager_WaitForTraffic_StaleListenerMustNotDisarmReplacement pins the
// identity guard in waitForTraffic: a stale goroutine (listener A) that loses
// the m.mu race against RemovePeer + re-arm (listener B, same conn ID) must
// neither delete B from the map nor fire an activity event.
func TestManager_WaitForTraffic_StaleListenerMustNotDisarmReplacement(t *testing.T) {
	mgr := NewManager(&MocWGIface{})
	defer mgr.Close()

	peer := &MocPeer{PeerID: "examplePublicKeyChurn"}
	connID := peer.ConnID()
	logger := log.WithField("peer", peer.PeerID)

	// Step 1: arm listener A; its goroutine blocks in ReadPackets.
	a := newFakeChurnListener()
	aDone := mgr.armListener(connID, a)

	// Step 2: RemovePeer closes A; A's goroutine is held right before
	// acquiring m.mu by the proceed gate.
	mgr.RemovePeer(logger, connID)

	// Step 3: re-arm a fresh listener B for the same conn ID.
	b := newFakeChurnListener()
	bDone := mgr.armListener(connID, b)

	// Step 4: A's goroutine loses the race only now.
	close(a.proceed)
	select {
	case <-aDone:
	case <-time.After(5 * time.Second): // hang protection only
		t.Fatal("listener A goroutine did not finish")
	}

	// Core asserts: B must stay armed, and A must not have fired an event.
	if cur, ok := mgr.GetPeerListener(connID); !ok || cur != listener(b) {
		t.Fatal("map entry must still be exactly listener B")
	}
	select {
	case ev := <-mgr.OnActivityChan:
		t.Fatalf("closed stale listener must not fire an event (got %v)", ev.PeerConnID)
	default:
	}

	// Step 5: B stays fully functional - traffic (released without Close,
	// then proceed) delivers exactly one event and B removes itself.
	b.captured = []byte{0x01}
	b.result = ActivityResultTraffic
	close(b.released)
	close(b.proceed)
	select {
	case <-bDone:
	case <-time.After(5 * time.Second):
		t.Fatal("listener B goroutine did not finish")
	}
	select {
	case ev := <-mgr.OnActivityChan:
		if ev.PeerConnID != connID {
			t.Fatalf("unexpected conn ID: %v", ev.PeerConnID)
		}
	default:
		t.Fatal("live listener B must deliver its traffic event")
	}
	if _, ok := mgr.GetPeerListener(connID); ok {
		t.Fatal("listener B must have removed itself after delivering traffic")
	}
}

// TestManager_WaitForTraffic_RealTrafficSurvivesRemoveRearm pins the reason
// contract: listener A consumes REAL traffic, then loses the m.mu race
// against RemovePeer + re-arm (B, same conn ID). B must stay armed
// (identity guard), but A's event including the captured packet must still
// be delivered - otherwise the first packet is blackholed (kernel mode:
// reinjection lost; userspace mode: the only wake edge lost).
func TestManager_WaitForTraffic_RealTrafficSurvivesRemoveRearm(t *testing.T) {
	mgr := NewManager(&MocWGIface{})
	defer mgr.Close()

	peer := &MocPeer{PeerID: "examplePublicKeyChurnTraffic"}
	connID := peer.ConnID()
	logger := log.WithField("peer", peer.PeerID)

	// Step 1: arm listener A; A will report real traffic.
	a := newFakeChurnListener()
	a.result = ActivityResultTraffic
	a.captured = []byte{0x04, 0x00, 0x00, 0x00, 0xAA, 0xBB}
	aDone := mgr.armListener(connID, a)

	// Step 2: A consumes traffic (released without Close) but is held right
	// before acquiring m.mu.
	close(a.released)

	// Step 3: RemovePeer + re-arm B run inside the race window.
	mgr.RemovePeer(logger, connID)
	b := newFakeChurnListener()
	bDone := mgr.armListener(connID, b)

	// Step 4: A's goroutine loses the race only now.
	close(a.proceed)
	select {
	case <-aDone:
	case <-time.After(5 * time.Second): // hang protection only
		t.Fatal("listener A goroutine did not finish")
	}

	// Core asserts: B stays armed AND A's real event is delivered.
	if cur, ok := mgr.GetPeerListener(connID); !ok || cur != listener(b) {
		t.Fatal("map entry must still be exactly listener B")
	}
	select {
	case ev := <-mgr.OnActivityChan:
		if ev.PeerConnID != connID {
			t.Fatalf("wrong conn ID in delivered event: %v", ev.PeerConnID)
		}
		if !bytes.Equal(ev.FirstPacket, a.captured) {
			t.Fatalf("event must carry A's captured packet, got %v", ev.FirstPacket)
		}
	default:
		t.Fatal("real traffic consumed by the raced-out listener must be delivered")
	}

	// Teardown: remove B via the close path - no further event.
	mgr.RemovePeer(logger, connID)
	close(b.proceed)
	select {
	case <-bDone:
	case <-time.After(5 * time.Second):
		t.Fatal("listener B goroutine did not finish")
	}
	select {
	case ev := <-mgr.OnActivityChan:
		t.Fatalf("closed listener B must not fire an event (got %v)", ev.PeerConnID)
	default:
	}
}

func trigger(addr string) error {
	// Create a connection to the destination UDP address and port
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Write the bytes to the UDP connection
	_, err = conn.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	if err != nil {
		return err
	}
	return nil
}
