package activity

import (
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

func TestUDPListener_Creation(t *testing.T) {
	mockIface := &MocWGIface{}

	peer := &MocPeer{PeerID: "testPeer1"}
	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	listener, err := NewUDPListener(mockIface, cfg)
	require.NoError(t, err)
	require.NotNil(t, listener.conn)
	require.NotNil(t, listener.endpoint)

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

func TestUDPListener_ActivityDetection(t *testing.T) {
	mockIface := &MocWGIface{}

	peer := &MocPeer{PeerID: "testPeer1"}
	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	listener, err := NewUDPListener(mockIface, cfg)
	require.NoError(t, err)

	activityDetected := make(chan struct{})
	go func() {
		listener.ReadPackets()
		close(activityDetected)
	}()

	conn, err := net.Dial("udp", listener.conn.LocalAddr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{0x01, 0x02, 0x03})
	require.NoError(t, err)

	select {
	case <-activityDetected:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for activity detection")
	}
}

func TestUDPListener_Close(t *testing.T) {
	mockIface := &MocWGIface{}

	peer := &MocPeer{PeerID: "testPeer1"}
	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Log:        log.WithField("peer", "testPeer1"),
	}

	listener, err := NewUDPListener(mockIface, cfg)
	require.NoError(t, err)

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

	assert.True(t, listener.isClosed.Load(), "Listener should be marked as closed")
}
