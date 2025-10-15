package activity

import (
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

// mockEndpointManager implements device.EndpointManager for testing
type mockEndpointManager struct {
	endpoints map[netip.Addr]net.Conn
}

func newMockEndpointManager() *mockEndpointManager {
	return &mockEndpointManager{
		endpoints: make(map[netip.Addr]net.Conn),
	}
}

func (m *mockEndpointManager) SetEndpoint(fakeIP netip.Addr, conn net.Conn) {
	m.endpoints[fakeIP] = conn
}

func (m *mockEndpointManager) RemoveEndpoint(fakeIP netip.Addr) {
	delete(m.endpoints, fakeIP)
}

func (m *mockEndpointManager) GetEndpoint(fakeIP netip.Addr) net.Conn {
	return m.endpoints[fakeIP]
}

// MockWGIfaceBind mocks WgInterface with bind support
type MockWGIfaceBind struct {
	endpointMgr *mockEndpointManager
}

func (m *MockWGIfaceBind) RemovePeer(string) error {
	return nil
}

func (m *MockWGIfaceBind) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	return nil
}

func (m *MockWGIfaceBind) IsUserspaceBind() bool {
	return true
}

func (m *MockWGIfaceBind) Address() wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/16"),
	}
}

func (m *MockWGIfaceBind) GetBind() device.EndpointManager {
	return m.endpointMgr
}

func TestBindListener_Creation(t *testing.T) {
	mockEndpointMgr := newMockEndpointManager()
	mockIface := &MockWGIfaceBind{endpointMgr: mockEndpointMgr}

	peer := &MocPeer{PeerID: "testPeer1"}
	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	listener, err := NewBindListener(mockIface, mockEndpointMgr, cfg)
	if err != nil {
		t.Fatalf("failed to create bind listener: %v", err)
	}

	// Verify endpoint was registered with the expected derived fake IP
	expectedFakeIP := netip.MustParseAddr("127.2.0.2")
	conn := mockEndpointMgr.GetEndpoint(expectedFakeIP)
	if conn == nil {
		t.Fatal("endpoint not registered in mock endpoint manager")
	}

	// Verify it's a lazyConn
	if _, ok := conn.(*lazyConn); !ok {
		t.Fatal("registered endpoint is not a lazyConn")
	}

	// Close properly
	readPacketsDone := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(readPacketsDone)
	}()

	listener.Close()

	select {
	case <-readPacketsDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ReadPackets to exit after Close")
	}
}

func TestBindListener_ActivityDetection(t *testing.T) {
	mockEndpointMgr := newMockEndpointManager()
	mockIface := &MockWGIfaceBind{endpointMgr: mockEndpointMgr}

	peer := &MocPeer{PeerID: "testPeer1"}
	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	listener, err := NewBindListener(mockIface, mockEndpointMgr, cfg)
	if err != nil {
		t.Fatalf("failed to create bind listener: %v", err)
	}

	activityDetected := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(activityDetected)
	}()

	// Get the lazyConn and simulate WireGuard sending data
	fakeIP := listener.fakeIP
	conn := mockEndpointMgr.GetEndpoint(fakeIP)
	if conn == nil {
		t.Fatal("endpoint not found")
	}

	// Simulate activity by writing to the lazyConn
	_, err = conn.Write([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("failed to write to lazyConn: %v", err)
	}

	// Wait for activity detection
	select {
	case <-activityDetected:
		// Success - activity was detected
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for activity detection")
	}

	// Verify endpoint was removed after activity
	if mockEndpointMgr.GetEndpoint(fakeIP) != nil {
		t.Fatal("endpoint should be removed after activity detection")
	}
}

func TestBindListener_Close(t *testing.T) {
	mockEndpointMgr := newMockEndpointManager()
	mockIface := &MockWGIfaceBind{endpointMgr: mockEndpointMgr}

	peer := &MocPeer{PeerID: "testPeer1"}
	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	listener, err := NewBindListener(mockIface, mockEndpointMgr, cfg)
	if err != nil {
		t.Fatalf("failed to create bind listener: %v", err)
	}

	readPacketsDone := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(readPacketsDone)
	}()

	// Close the listener
	fakeIP := listener.fakeIP
	listener.Close()

	// Wait for ReadPackets to exit
	select {
	case <-readPacketsDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ReadPackets to exit after Close")
	}

	// Verify endpoint was removed
	if mockEndpointMgr.GetEndpoint(fakeIP) != nil {
		t.Fatal("endpoint should be removed after Close")
	}
}

func TestManager_BindMode(t *testing.T) {
	mockEndpointMgr := newMockEndpointManager()
	mockIface := &MockWGIfaceBind{endpointMgr: mockEndpointMgr}

	peer := &MocPeer{PeerID: "testPeer1"}
	mgr := NewManager(mockIface)
	defer mgr.Close()

	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	if err := mgr.MonitorPeerActivity(cfg); err != nil {
		t.Fatalf("failed to monitor peer activity: %v", err)
	}

	listener, exists := mgr.GetPeerListener(cfg.PeerConnID)
	if !exists {
		t.Fatal("peer listener not found")
	}

	// Verify it's a BindListener
	bindListener, ok := listener.(*BindListener)
	if !ok {
		t.Fatalf("expected BindListener, got %T", listener)
	}

	// Get the lazyConn and simulate activity
	fakeIP := bindListener.fakeIP
	conn := mockEndpointMgr.GetEndpoint(fakeIP)
	if conn == nil {
		t.Fatal("endpoint not registered")
	}

	// Simulate WireGuard sending packet
	_, err := conn.Write([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("failed to write to lazyConn: %v", err)
	}

	// Wait for activity notification
	select {
	case peerConnID := <-mgr.OnActivityChan:
		if peerConnID != cfg.PeerConnID {
			t.Fatalf("unexpected peerConnID: %v", peerConnID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for activity notification")
	}

	// Verify endpoint was removed after activity
	if mockEndpointMgr.GetEndpoint(fakeIP) != nil {
		t.Fatal("endpoint should be removed after activity")
	}
}

func TestManager_BindMode_MultiplePeers(t *testing.T) {
	mockEndpointMgr := newMockEndpointManager()
	mockIface := &MockWGIfaceBind{endpointMgr: mockEndpointMgr}

	peer1 := &MocPeer{PeerID: "testPeer1"}
	peer2 := &MocPeer{PeerID: "testPeer2"}
	mgr := NewManager(mockIface)
	defer mgr.Close()

	cfg1 := lazyconn.PeerConfig{
		PublicKey:  peer1.PeerID,
		PeerConnID: peer1.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	cfg2 := lazyconn.PeerConfig{
		PublicKey:  peer2.PeerID,
		PeerConnID: peer2.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Log:        log.WithField("peer", "testPeer2"),
	}

	if err := mgr.MonitorPeerActivity(cfg1); err != nil {
		t.Fatalf("failed to monitor peer1: %v", err)
	}

	if err := mgr.MonitorPeerActivity(cfg2); err != nil {
		t.Fatalf("failed to monitor peer2: %v", err)
	}

	// Get both listeners
	listener1, exists := mgr.GetPeerListener(cfg1.PeerConnID)
	if !exists {
		t.Fatal("peer1 listener not found")
	}
	bindListener1 := listener1.(*BindListener)

	listener2, exists := mgr.GetPeerListener(cfg2.PeerConnID)
	if !exists {
		t.Fatal("peer2 listener not found")
	}
	bindListener2 := listener2.(*BindListener)

	// Trigger activity on peer1
	conn1 := mockEndpointMgr.GetEndpoint(bindListener1.fakeIP)
	if conn1 == nil {
		t.Fatal("peer1 endpoint not registered")
	}
	_, err := conn1.Write([]byte{0x01})
	if err != nil {
		t.Fatalf("failed to write to peer1 lazyConn: %v", err)
	}

	// Trigger activity on peer2
	conn2 := mockEndpointMgr.GetEndpoint(bindListener2.fakeIP)
	if conn2 == nil {
		t.Fatal("peer2 endpoint not registered")
	}
	_, err = conn2.Write([]byte{0x02})
	if err != nil {
		t.Fatalf("failed to write to peer2 lazyConn: %v", err)
	}

	// Wait for both activities
	receivedPeers := make(map[peerid.ConnID]bool)
	for i := 0; i < 2; i++ {
		select {
		case peerConnID := <-mgr.OnActivityChan:
			receivedPeers[peerConnID] = true
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for activity notifications")
		}
	}

	if !receivedPeers[cfg1.PeerConnID] {
		t.Fatal("peer1 activity not received")
	}
	if !receivedPeers[cfg2.PeerConnID] {
		t.Fatal("peer2 activity not received")
	}
}
