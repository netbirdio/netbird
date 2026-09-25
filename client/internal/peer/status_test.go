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

func TestUpdateLatencyNotifiesRouteWatchers(t *testing.T) {
	key := "abc"
	status := NewRecorder("https://mgm")
	require.NoError(t, status.AddPeer(key, "abc.netbird", "100.108.254.1", ""))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sub := status.SubscribeToPeerStateChanges(ctx, key)

	require.NoError(t, status.UpdateLatency(key, LatencySample{Latency: 40 * time.Millisecond}))
	select {
	case states := <-sub.Events():
		assert.Equal(t, 40*time.Millisecond, states[key].Latency, "the notified state should carry the new latency")
	default:
		t.Fatal("expected a router state notification for the first latency sample")
	}

	// below routerLatencyNotifyThreshold: recorded, but not worth waking the watchers
	require.NoError(t, status.UpdateLatency(key, LatencySample{Latency: 42 * time.Millisecond}))
	select {
	case <-sub.Events():
		t.Fatal("a latency change below the threshold should not notify")
	default:
	}

	peerState, err := status.GetPeer(key)
	require.NoError(t, err)
	assert.Equal(t, 42*time.Millisecond, peerState.Latency, "the latency should be recorded even without a notification")

	require.NoError(t, status.UpdateLatency(key, LatencySample{Latency: 100 * time.Millisecond}))
	select {
	case states := <-sub.Events():
		assert.Equal(t, 100*time.Millisecond, states[key].Latency, "a significant latency change should notify")
	default:
		t.Fatal("expected a router state notification for a significant latency change")
	}

	// the noise feeds the switch margin, so a large change in it matters on its
	// own even when the latency stays put
	require.NoError(t, status.UpdateLatency(key, LatencySample{Latency: 100 * time.Millisecond, Noise: 20 * time.Millisecond}))
	select {
	case states := <-sub.Events():
		assert.Equal(t, 20*time.Millisecond, states[key].LatencyNoise, "a significant noise change should notify")
	default:
		t.Fatal("expected a router state notification for a significant noise change")
	}

	require.NoError(t, status.UpdateLatency(key, LatencySample{Latency: 100 * time.Millisecond, Noise: 21 * time.Millisecond}))
	select {
	case <-sub.Events():
		t.Fatal("a noise change below the threshold should not notify")
	default:
	}
}

// TestSubscriptionDeliverOrdering covers the sequence stamping: snapshots are
// built under the status lock but delivered outside it, so a dispatcher that
// is descheduled between the two can deliver an outdated snapshot after a
// newer one. The older snapshot must be dropped, not delivered.
func TestSubscriptionDeliverOrdering(t *testing.T) {
	sub := newStatusChangeSubscription(context.Background(), "peer")

	newer := &routerSnapshot{seq: 2, states: map[string]RouterState{"peer": {Status: StatusConnecting}}}
	older := &routerSnapshot{seq: 1, states: map[string]RouterState{"peer": {Status: StatusConnected}}}

	sub.deliver(newer, true)
	sub.deliver(older, true)

	select {
	case states := <-sub.Events():
		assert.Equal(t, StatusConnecting, states["peer"].Status, "the newer snapshot should be delivered")
	default:
		t.Fatal("expected the newer snapshot to be delivered")
	}

	select {
	case <-sub.Events():
		t.Fatal("the outdated snapshot must be dropped, not delivered after the newer one")
	default:
	}
}

// TestSubscriptionDeliverNonBlocking covers the latency dispatch path: a
// backlogged subscriber must not block the sender, and the dropped snapshot is
// recovered from the recorder by the route watchers' periodic re-evaluation.
func TestSubscriptionDeliverNonBlocking(t *testing.T) {
	sub := newStatusChangeSubscription(context.Background(), "peer")

	// fill the subscription buffer with no consumer draining it
	seq := uint64(1)
	for {
		before := len(sub.eventsChan)
		sub.deliver(&routerSnapshot{seq: seq, states: map[string]RouterState{}}, false)
		seq++
		if len(sub.eventsChan) == before {
			break
		}
	}

	done := make(chan struct{})
	go func() {
		sub.deliver(&routerSnapshot{seq: seq, states: map[string]RouterState{}}, false)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a non-blocking deliver must return with the buffer full")
	}
}

// A snapshot the subscriber never received must not count as delivered: a
// state transition dispatched just before it, but delivered just after, would
// otherwise be dropped as outdated and never reach the subscriber.
func TestSubscriptionDroppedDeliveryDoesNotSupersede(t *testing.T) {
	sub := newStatusChangeSubscription(context.Background(), "peer")

	for seq := uint64(1); seq <= uint64(cap(sub.eventsChan)); seq++ {
		sub.deliver(&routerSnapshot{seq: seq, states: map[string]RouterState{}}, false)
	}
	require.Len(t, sub.eventsChan, cap(sub.eventsChan), "the buffer must be full")

	// a latency refresh stamped after the transition wins the race to the
	// subscriber and is dropped on the full buffer
	transition := &routerSnapshot{seq: 100, states: map[string]RouterState{"peer": {Status: StatusConnecting}}}
	latency := &routerSnapshot{seq: 101, states: map[string]RouterState{"peer": {Status: StatusConnected}}}
	sub.deliver(latency, false)

	for range cap(sub.eventsChan) {
		<-sub.eventsChan
	}
	sub.deliver(transition, true)

	select {
	case states := <-sub.Events():
		assert.Equal(t, StatusConnecting, states["peer"].Status, "the transition must be delivered")
	default:
		t.Fatal("a transition must not be dropped because a later snapshot was dropped")
	}
}

// Latency is only measured over a direct connection. Once it is gone the last
// sample describes a path the traffic no longer takes, and must not be compared
// against other routing peers as if it were current.
func TestLatencyClearedWithDirectConnection(t *testing.T) {
	const key = "abc"

	newStatus := func(t *testing.T) *Status {
		t.Helper()
		status := NewRecorder("https://mgm")
		require.NoError(t, status.AddPeer(key, "peer-a.netbird.local", "10.10.10.10", ""))
		require.NoError(t, status.UpdatePeerICEState(State{PubKey: key, ConnStatus: StatusConnected}))
		require.NoError(t, status.UpdateLatency(key, LatencySample{Latency: 20 * time.Millisecond, Noise: time.Millisecond}))
		return status
	}

	assertCleared := func(t *testing.T, status *Status) {
		t.Helper()
		state, err := status.GetPeer(key)
		require.NoError(t, err)
		assert.Zero(t, state.Latency, "the latency of the lost direct path must be cleared")
		assert.Zero(t, state.LatencyNoise, "the noise of the lost direct path must be cleared")
	}

	t.Run("ice disconnected, relayed", func(t *testing.T) {
		status := newStatus(t)
		require.NoError(t, status.UpdatePeerICEStateToDisconnected(State{PubKey: key, ConnStatus: StatusConnected, Relayed: true}))
		assertCleared(t, status)
	})

	t.Run("connection closed", func(t *testing.T) {
		status := newStatus(t)
		require.NoError(t, status.UpdatePeerState(State{PubKey: key, ConnStatus: StatusIdle}))
		assertCleared(t, status)
	})
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

// TestStatus_GetPeerStates_IncludesOfflinePeers keeps the snapshot in line with
// GetFullStatus: offline peers are known peers, so a consumer counting peers
// must see the same total the status command reports.
func TestStatus_GetPeerStates_IncludesOfflinePeers(t *testing.T) {
	status := NewRecorder("https://mgm")
	req := require.New(t)

	req.NoError(status.AddPeer("pk-online", "online.netbird", "100.64.0.10", "fd00::1"))
	status.ReplaceOfflinePeers([]State{
		{PubKey: "pk-offline", FQDN: "offline.netbird", IP: "100.64.0.20", ConnStatus: StatusIdle},
	})

	states := status.GetPeerStates()
	req.Len(states, 2, "snapshot must carry both the online and the offline peer")

	keys := make([]string, 0, len(states))
	for _, s := range states {
		keys = append(keys, s.PubKey)
	}
	req.ElementsMatch([]string{"pk-online", "pk-offline"}, keys, "snapshot must carry both peers")
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

// notified reports whether a state-change tick is pending on ch, draining it.
func notified(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestMarkServerStateDoesNotNotifyWhenUnchanged(t *testing.T) {
	status := NewRecorder("https://mgm")
	_, ch := status.SubscribeToStateChanges()

	// First transition is a real change and must notify.
	status.MarkManagementConnected()
	require.True(t, notified(ch), "first connect should notify")

	// Re-marking the same state must not notify again.
	status.MarkManagementConnected()
	assert.False(t, notified(ch), "redundant connect should not notify")

	// Same for signal.
	status.MarkSignalConnected()
	require.True(t, notified(ch), "first signal connect should notify")
	status.MarkSignalConnected()
	assert.False(t, notified(ch), "redundant signal connect should not notify")

	// A genuine change (disconnect with an error) notifies again.
	err := errors.New("boom")
	status.MarkManagementDisconnected(err)
	require.True(t, notified(ch), "disconnect should notify")
	status.MarkManagementDisconnected(err)
	assert.False(t, notified(ch), "redundant disconnect should not notify")
}
