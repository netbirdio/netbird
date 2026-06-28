package peer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddPeer(t *testing.T) {
	key := "abc"
	ip := "100.108.254.1"
	status := NewRecorder("https://mgm")
	err := status.AddPeer(key, "abc.netbird", ip, "")
	assert.NoError(t, err, "shouldn't return error")

	_, exists := status.peers[key]
	assert.True(t, exists, "value was found")

	err = status.AddPeer(key, "abc.netbird", ip, "")

	assert.Error(t, err, "should return error on duplicate")
}

func TestGetPeer(t *testing.T) {
	key := "abc"
	ip := "100.108.254.1"
	status := NewRecorder("https://mgm")
	err := status.AddPeer(key, "abc.netbird", ip, "")
	assert.NoError(t, err, "shouldn't return error")

	peerStatus, err := status.GetPeer(key)
	assert.NoError(t, err, "shouldn't return error on getting peer")

	assert.Equal(t, key, peerStatus.PubKey, "retrieved public key should match")

	_, err = status.GetPeer("non_existing_key")
	assert.Error(t, err, "should return error when peer doesn't exist")
}

func TestUpdatePeerState(t *testing.T) {
	key := "abc"
	ip := "10.10.10.10"
	fqdn := "peer-a.netbird.local"
	status := NewRecorder("https://mgm")
	require.NoError(t, status.AddPeer(key, fqdn, ip, ""))

	peerState := State{
		PubKey:           key,
		ConnStatusUpdate: time.Now(),
		ConnStatus:       StatusConnecting,
	}

	err := status.UpdatePeerState(peerState)
	assert.NoError(t, err, "shouldn't return error")

	state, exists := status.peers[key]
	assert.True(t, exists, "state should be found")
	assert.Equal(t, ip, state.IP, "ip should be equal")
}

func TestStatus_PeerStateByIP(t *testing.T) {
	status := NewRecorder("https://mgm")
	req := require.New(t)

	req.NoError(status.AddPeer("pk-1", "peer-1.netbird", "100.64.0.10", ""))
	req.NoError(status.AddPeer("pk-2", "peer-2.netbird", "100.64.0.11", ""))

	state, ok := status.PeerStateByIP("100.64.0.10")
	req.True(ok, "known tunnel IP should resolve to a peer state")
	req.Equal("pk-1", state.PubKey, "matching state must carry the right pub key")
	req.Equal("peer-1.netbird", state.FQDN, "matching state must carry the right FQDN")

	_, ok = status.PeerStateByIP("100.64.0.99")
	req.False(ok, "unknown IP must report ok=false")
}

func TestStatus_PeerStateByIP_MatchesIPv6(t *testing.T) {
	status := NewRecorder("https://mgm")
	req := require.New(t)

	req.NoError(status.AddPeer("pk-1", "peer-1.netbird", "100.64.0.10", "fd00::1"))

	state, ok := status.PeerStateByIP("fd00::1")
	req.True(ok, "IPv6-only match must resolve to the peer state")
	req.Equal("pk-1", state.PubKey, "matching state must carry the right pub key")
}

// TestStatus_PeerStateByIP_IgnoresOfflinePeers documents that peers
// moved into the offline slice via ReplaceOfflinePeers are intentionally
// not resolvable by IP: only active peers can carry traffic, so callers
// (DNS filter, embed.Client.IdentityForIP) treat them as unknown.
func TestStatus_PeerStateByIP_IgnoresOfflinePeers(t *testing.T) {
	status := NewRecorder("https://mgm")
	req := require.New(t)

	status.ReplaceOfflinePeers([]State{
		{PubKey: "pk-offline", FQDN: "offline.netbird", IP: "100.64.0.20", IPv6: "fd00::20"},
	})

	_, ok := status.PeerStateByIP("100.64.0.20")
	req.False(ok, "offline peer must not resolve by IPv4 tunnel address")

	_, ok = status.PeerStateByIP("fd00::20")
	req.False(ok, "offline peer must not resolve by IPv6 tunnel address")
}

// TestStatus_PeerStateByIP_RemovedPeer verifies RemovePeer drops the
// IP index entries for both address families.
func TestStatus_PeerStateByIP_RemovedPeer(t *testing.T) {
	status := NewRecorder("https://mgm")
	req := require.New(t)

	req.NoError(status.AddPeer("pk-1", "peer-1.netbird", "100.64.0.10", "fd00::1"))

	_, ok := status.PeerStateByIP("100.64.0.10")
	req.True(ok, "active peer must resolve before removal")

	req.NoError(status.RemovePeer("pk-1"))

	_, ok = status.PeerStateByIP("100.64.0.10")
	req.False(ok, "removed peer must not resolve by IPv4 tunnel address")

	_, ok = status.PeerStateByIP("fd00::1")
	req.False(ok, "removed peer must not resolve by IPv6 tunnel address")
}

func TestStatus_UpdatePeerFQDN(t *testing.T) {
	key := "abc"
	fqdn := "peer-a.netbird.local"
	status := NewRecorder("https://mgm")
	peerState := State{
		PubKey: key,
		Mux:    new(sync.RWMutex),
	}

	status.peers[key] = peerState

	err := status.UpdatePeerFQDN(key, fqdn)
	assert.NoError(t, err, "shouldn't return error")

	state, exists := status.peers[key]
	assert.True(t, exists, "state should be found")
	assert.Equal(t, fqdn, state.FQDN, "fqdn should be equal")
}

func TestGetPeerStateChangeNotifierLogic(t *testing.T) {
	key := "abc"
	ip := "10.10.10.10"
	status := NewRecorder("https://mgm")
	_ = status.AddPeer(key, "abc.netbird", ip, "")

	sub := status.SubscribeToPeerStateChanges(context.Background(), key)
	assert.NotNil(t, sub, "channel shouldn't be nil")

	peerState := State{
		PubKey:           key,
		ConnStatus:       StatusConnecting,
		Relayed:          false,
		ConnStatusUpdate: time.Now(),
	}

	err := status.UpdatePeerRelayedStateToDisconnected(peerState)
	assert.NoError(t, err, "shouldn't return error")

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	select {
	case <-sub.eventsChan:
	case <-timeoutCtx.Done():
		t.Errorf("timed out waiting for event")
	}
}

func TestRemovePeer(t *testing.T) {
	key := "abc"
	status := NewRecorder("https://mgm")
	peerState := State{
		PubKey: key,
		Mux:    new(sync.RWMutex),
	}

	status.peers[key] = peerState

	err := status.RemovePeer(key)
	assert.NoError(t, err, "shouldn't return error")

	_, exists := status.peers[key]
	assert.False(t, exists, "state value shouldn't be found")

	err = status.RemovePeer("not existing")
	assert.Error(t, err, "should return error when peer doesn't exist")
}

func TestUpdateLocalPeerState(t *testing.T) {
	localPeerState := LocalPeerState{
		IP:              "10.10.10.10",
		PubKey:          "abc",
		KernelInterface: false,
	}
	status := NewRecorder("https://mgm")

	status.UpdateLocalPeerState(localPeerState)

	assert.Equal(t, localPeerState, status.localPeer, "local peer status should be equal")
}

func TestCleanLocalPeerState(t *testing.T) {
	emptyLocalPeerState := LocalPeerState{}
	localPeerState := LocalPeerState{
		IP:              "10.10.10.10",
		PubKey:          "abc",
		KernelInterface: false,
	}
	status := NewRecorder("https://mgm")

	status.localPeer = localPeerState

	status.CleanLocalPeerState()

	assert.Equal(t, emptyLocalPeerState, status.localPeer, "local peer status should be empty")
}

func TestUpdateSignalState(t *testing.T) {
	url := "https://signal"
	var tests = []struct {
		name      string
		connected bool
		want      bool
		err       error
	}{
		{"should mark as connected", true, true, nil},
		{"should mark as disconnected", false, false, errors.New("test")},
	}

	status := NewRecorder("https://mgm")
	status.UpdateSignalAddress(url)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.connected {
				status.MarkSignalConnected()
			} else {
				status.MarkSignalDisconnected(test.err)
			}
			assert.Equal(t, test.want, status.signalState, "signal status should be equal")
			assert.Equal(t, test.err, status.signalError)
		})
	}
}

func TestUpdateManagementState(t *testing.T) {
	url := "https://management"
	var tests = []struct {
		name      string
		connected bool
		want      bool
		err       error
	}{
		{"should mark as connected", true, true, nil},
		{"should mark as disconnected", false, false, errors.New("test")},
	}

	status := NewRecorder(url)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.connected {
				status.MarkManagementConnected()
			} else {
				status.MarkManagementDisconnected(test.err)
			}
			assert.Equal(t, test.want, status.managementState, "signalState status should be equal")
			assert.Equal(t, test.err, status.managementError)
		})
	}
}

func TestGetFullStatus(t *testing.T) {
	key1 := "abc"
	key2 := "def"
	signalAddr := "https://signal"
	managementState := ManagementState{
		URL:       "https://mgm",
		Connected: true,
	}
	signalState := SignalState{
		URL:       signalAddr,
		Connected: true,
	}
	peerState1 := State{
		PubKey: key1,
	}

	peerState2 := State{
		PubKey: key2,
	}

	status := NewRecorder("https://mgm")
	status.UpdateSignalAddress(signalAddr)

	status.managementState = managementState.Connected
	status.signalState = signalState.Connected
	status.peers[key1] = peerState1
	status.peers[key2] = peerState2

	fullStatus := status.GetFullStatus()

	assert.Equal(t, managementState, fullStatus.ManagementState, "management status should be equal")
	assert.Equal(t, signalState, fullStatus.SignalState, "signal status should be equal")
	assert.ElementsMatch(t, []State{peerState1, peerState2}, fullStatus.Peers, "peers states should match")
}
