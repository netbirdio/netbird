package activity

import (
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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

// Add this method to the Manager struct
func (m *Manager) GetPeerListener(peerConnID peerid.ConnID) (*Listener, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, exists := m.peers[peerConnID]
	return listener, exists
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

	if err := trigger(listener.conn.LocalAddr().String()); err != nil {
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

	addr := mgr.peers[peerCfg1.PeerConnID].conn.LocalAddr().String()

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

	if err := trigger(listener.conn.LocalAddr().String()); err != nil {
		t.Fatalf("failed to trigger activity: %v", err)
	}

	listener, exists = mgr.GetPeerListener(peerCfg2.PeerConnID)
	if !exists {
		t.Fatalf("peer listener for peer1 not found")
	}

	if err := trigger(listener.conn.LocalAddr().String()); err != nil {
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
