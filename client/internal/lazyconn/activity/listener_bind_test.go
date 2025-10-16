package activity

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

func isBindListenerPlatform() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "js"
}

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
	require.NoError(t, err)

	expectedFakeIP := netip.MustParseAddr("127.2.0.2")
	conn := mockEndpointMgr.GetEndpoint(expectedFakeIP)
	require.NotNil(t, conn, "Endpoint should be registered in mock endpoint manager")

	_, ok := conn.(*lazyConn)
	assert.True(t, ok, "Registered endpoint should be a lazyConn")

	readPacketsDone := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(readPacketsDone)
	}()

	listener.Close()

	select {
	case <-readPacketsDone:
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
	require.NoError(t, err)

	activityDetected := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(activityDetected)
	}()

	fakeIP := listener.fakeIP
	conn := mockEndpointMgr.GetEndpoint(fakeIP)
	require.NotNil(t, conn, "Endpoint should be registered")

	_, err = conn.Write([]byte{0x01, 0x02, 0x03})
	require.NoError(t, err)

	select {
	case <-activityDetected:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for activity detection")
	}

	assert.Nil(t, mockEndpointMgr.GetEndpoint(fakeIP), "Endpoint should be removed after activity detection")
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
	require.NoError(t, err)

	readPacketsDone := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(readPacketsDone)
	}()

	fakeIP := listener.fakeIP
	listener.Close()

	select {
	case <-readPacketsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ReadPackets to exit after Close")
	}

	assert.Nil(t, mockEndpointMgr.GetEndpoint(fakeIP), "Endpoint should be removed after Close")
}

func TestManager_BindMode(t *testing.T) {
	if !isBindListenerPlatform() {
		t.Skip("BindListener only used on Windows/JS platforms")
	}

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

	err := mgr.MonitorPeerActivity(cfg)
	require.NoError(t, err)

	listener, exists := mgr.GetPeerListener(cfg.PeerConnID)
	require.True(t, exists, "Peer listener should be found")

	bindListener, ok := listener.(*BindListener)
	require.True(t, ok, "Listener should be BindListener, got %T", listener)

	fakeIP := bindListener.fakeIP
	conn := mockEndpointMgr.GetEndpoint(fakeIP)
	require.NotNil(t, conn, "Endpoint should be registered")

	_, err = conn.Write([]byte{0x01, 0x02, 0x03})
	require.NoError(t, err)

	select {
	case peerConnID := <-mgr.OnActivityChan:
		assert.Equal(t, cfg.PeerConnID, peerConnID, "Received peer connection ID should match")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for activity notification")
	}

	assert.Nil(t, mockEndpointMgr.GetEndpoint(fakeIP), "Endpoint should be removed after activity")
}

func TestManager_BindMode_MultiplePeers(t *testing.T) {
	if !isBindListenerPlatform() {
		t.Skip("BindListener only used on Windows/JS platforms")
	}

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

	err := mgr.MonitorPeerActivity(cfg1)
	require.NoError(t, err)

	err = mgr.MonitorPeerActivity(cfg2)
	require.NoError(t, err)

	listener1, exists := mgr.GetPeerListener(cfg1.PeerConnID)
	require.True(t, exists, "Peer1 listener should be found")
	bindListener1 := listener1.(*BindListener)

	listener2, exists := mgr.GetPeerListener(cfg2.PeerConnID)
	require.True(t, exists, "Peer2 listener should be found")
	bindListener2 := listener2.(*BindListener)

	conn1 := mockEndpointMgr.GetEndpoint(bindListener1.fakeIP)
	require.NotNil(t, conn1, "Peer1 endpoint should be registered")
	_, err = conn1.Write([]byte{0x01})
	require.NoError(t, err)

	conn2 := mockEndpointMgr.GetEndpoint(bindListener2.fakeIP)
	require.NotNil(t, conn2, "Peer2 endpoint should be registered")
	_, err = conn2.Write([]byte{0x02})
	require.NoError(t, err)

	receivedPeers := make(map[peerid.ConnID]bool)
	for i := 0; i < 2; i++ {
		select {
		case peerConnID := <-mgr.OnActivityChan:
			receivedPeers[peerConnID] = true
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for activity notifications")
		}
	}

	assert.True(t, receivedPeers[cfg1.PeerConnID], "Peer1 activity should be received")
	assert.True(t, receivedPeers[cfg2.PeerConnID], "Peer2 activity should be received")
}
