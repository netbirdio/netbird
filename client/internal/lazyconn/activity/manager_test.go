package activity

import (
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

func (m MocWGIface) RemovePeer(string) error {
	return nil
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
	case peerConnID := <-mgr.OnActivityChan:
		if peerConnID != peerCfg1.PeerConnID {
			t.Fatalf("unexpected peerConnID: %v", peerConnID)
		}
	case <-time.After(1 * time.Second):
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
