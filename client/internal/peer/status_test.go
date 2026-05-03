package peer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAddPeer(t *testing.T) {
	key := "abc"
	ip := "100.108.254.1"
	status := NewRecorder("https://mgm")
	err := status.AddPeer(key, "abc.netbird", ip)
	assert.NoError(t, err, "shouldn't return error")

	_, exists := status.peers[key]
	assert.True(t, exists, "value was found")

	err = status.AddPeer(key, "abc.netbird", ip)

	assert.Error(t, err, "should return error on duplicate")
}

func TestGetPeer(t *testing.T) {
	key := "abc"
	ip := "100.108.254.1"
	status := NewRecorder("https://mgm")
	err := status.AddPeer(key, "abc.netbird", ip)
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
	_ = status.AddPeer(key, fqdn, ip)

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
	_ = status.AddPeer(key, "abc.netbird", ip)

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

	// GetFullStatus sets ServerOnline=true for peers in d.peers.
	peerState1.ServerOnline = true
	peerState2.ServerOnline = true

	assert.Equal(t, managementState, fullStatus.ManagementState, "management status should be equal")
	assert.Equal(t, signalState, fullStatus.SignalState, "signal status should be equal")
	assert.ElementsMatch(t, []State{peerState1, peerState2}, fullStatus.Peers, "peers states should match")
}

// TestStatus_ConnStateListener_CalledAfterUnlock verifies that the
// connStateListener registered via SetConnStateListener is invoked AFTER
// d.mux is released (Extract-Method guarantee). Phase 3.7i of #5989.
func TestStatus_ConnStateListener_CalledAfterUnlock(t *testing.T) {
	d := NewRecorder("")
	var listenerCalled atomic.Bool
	var listenerObservedLockHeld atomic.Bool

	d.SetConnStateListener(func(_ string, _ State) {
		// Try TryLock — if the locked body still holds mux this returns
		// false. We record the result so the assertion below can report it.
		if d.mux.TryLock() {
			listenerObservedLockHeld.Store(false)
			d.mux.Unlock()
		} else {
			listenerObservedLockHeld.Store(true)
		}
		listenerCalled.Store(true)
	})

	if err := d.AddPeer("peerA", "fqdn-A", "100.64.0.1"); err != nil {
		t.Fatal(err)
	}
	// Trigger a ConnStatus transition (Idle -> Connected) which must fire
	// the listener through updatePeerStateLocked.
	if err := d.UpdatePeerState(State{
		PubKey:           "peerA",
		ConnStatus:       StatusConnected,
		ConnStatusUpdate: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	if !listenerCalled.Load() {
		t.Error("listener not invoked")
	}
	if listenerObservedLockHeld.Load() {
		t.Error("listener called while mux still held — Extract-Method refactor incomplete")
	}
}

// TestStatus_UpdatePeerRemoteMeta_PreservesConnStatus verifies that
// UpdatePeerRemoteMeta sets Remote* fields without touching ConnStatus.
// Phase 3.7i of #5989.
func TestStatus_UpdatePeerRemoteMeta_PreservesConnStatus(t *testing.T) {
	d := NewRecorder("")
	// Add a peer first so it exists in d.peers (the map).
	if err := d.AddPeer("peerA", "fqdnA", "100.64.0.2"); err != nil {
		t.Fatal(err)
	}
	// Set its ConnStatus to Connected so we can verify it is preserved.
	if err := d.UpdatePeerState(State{
		PubKey:     "peerA",
		ConnStatus: StatusConnected,
		Relayed:    false,
	}); err != nil {
		t.Fatal(err)
	}

	if err := d.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		EffectiveConnectionMode: "p2p-dynamic",
		Groups:                  []string{"router"},
	}); err != nil {
		t.Fatal(err)
	}

	d.mux.Lock()
	got := d.peers["peerA"]
	d.mux.Unlock()
	if got.ConnStatus != StatusConnected {
		t.Errorf("ConnStatus changed: %v", got.ConnStatus)
	}
	if got.RemoteEffectiveConnectionMode != "p2p-dynamic" {
		t.Errorf("EffectiveMode not set: %s", got.RemoteEffectiveConnectionMode)
	}
	if len(got.RemoteGroups) != 1 || got.RemoteGroups[0] != "router" {
		t.Errorf("Groups not set: %v", got.RemoteGroups)
	}
}

// TestStatus_GetFullStatus_SetsServerOnlineAndCounters verifies aggregate
// counters and ServerOnline flag set in GetFullStatus. Phase 3.7i of #5989.
func TestStatus_GetFullStatus_SetsServerOnlineAndCounters(t *testing.T) {
	d := NewRecorder("")
	d.mux.Lock()
	d.peers["a"] = State{PubKey: "a", ConnStatus: StatusConnected, Relayed: false}
	d.peers["b"] = State{PubKey: "b", ConnStatus: StatusConnected, Relayed: true}
	d.peers["c"] = State{PubKey: "c", ConnStatus: StatusIdle}
	d.offlinePeers = []State{{PubKey: "d"}}
	d.mux.Unlock()

	fs := d.GetFullStatus()
	if fs.P2PConnectedPeers != 1 || fs.RelayedConnectedPeers != 1 ||
		fs.IdleOnlinePeers != 1 || fs.ServerOfflinePeers != 1 ||
		fs.ConfiguredPeersTotal != 4 {
		t.Errorf("counters wrong: P2P=%d Relayed=%d Idle=%d Offline=%d Total=%d",
			fs.P2PConnectedPeers, fs.RelayedConnectedPeers,
			fs.IdleOnlinePeers, fs.ServerOfflinePeers, fs.ConfiguredPeersTotal)
	}
	for _, st := range fs.Peers {
		if st.PubKey == "d" && st.ServerOnline {
			t.Error("offline peer must have ServerOnline=false")
		}
		if st.PubKey != "d" && !st.ServerOnline {
			t.Errorf("online peer %s must have ServerOnline=true", st.PubKey)
		}
	}
}
