package peer

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// recordingListener captures OnPeersListChanged calls for assertion.
// Other Listener methods are no-ops because UpdatePeerRemoteMeta only
// triggers the peer-list path.
type recordingListener struct {
	peersChangedCount atomic.Int32
}

func (r *recordingListener) OnConnected()                   {}
func (r *recordingListener) OnDisconnected()                {}
func (r *recordingListener) OnConnecting()                  {}
func (r *recordingListener) OnDisconnecting()               {}
func (r *recordingListener) OnAddressChanged(string, string) {}
func (r *recordingListener) OnPeersListChanged(int) {
	r.peersChangedCount.Add(1)
}

func waitForCount(t *testing.T, l *recordingListener, atLeast int32, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if l.peersChangedCount.Load() >= atLeast {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: timed out waiting for OnPeersListChanged count >= %d (got %d)",
		label, atLeast, l.peersChangedCount.Load())
}

// Codex finding 3: UpdatePeerRemoteMeta must fire OnPeersListChanged
// when a UI-relevant field flips (LiveOnline, ServerLivenessKnown,
// EffectiveConnectionMode), so the Android peer-list refreshes
// immediately instead of at the next 30 s daemon-RPC poll.

func TestStatus_UpdatePeerRemoteMeta_LiveOnlineFlipNotifies(t *testing.T) {
	rec := NewRecorder("https://mgm")
	listener := &recordingListener{}
	rec.SetConnectionListener(listener)
	if err := rec.AddPeer("peerA", "fqdn", "10.0.0.1"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	// setListener fires an initial OnPeersListChanged; wait for it.
	waitForCount(t, listener, 1, "initial setListener")

	// Baseline RemoteMeta with liveness=true, no notification expected
	// because the freshly-added peer's RemoteLiveOnline default is false
	// vs. true → that's a flip on the FIRST update too. Reset counter
	// after baseline so the rest of the test only counts flips.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		LiveOnline: true, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("baseline UpdatePeerRemoteMeta: %v", err)
	}
	waitForCount(t, listener, 2, "first flip from default")
	listener.peersChangedCount.Store(0)

	// Repeat the SAME meta — must NOT notify (no flip).
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		LiveOnline: true, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("idempotent UpdatePeerRemoteMeta: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), listener.peersChangedCount.Load(),
		"identical meta must not fire notification")

	// Flip true → false: must notify.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		LiveOnline: false, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("flip true->false UpdatePeerRemoteMeta: %v", err)
	}
	waitForCount(t, listener, 1, "true->false flip")
	listener.peersChangedCount.Store(0)

	// Flip back false → true: must notify.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		LiveOnline: true, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("flip false->true UpdatePeerRemoteMeta: %v", err)
	}
	waitForCount(t, listener, 1, "false->true flip")
}

func TestStatus_UpdatePeerRemoteMeta_EffectiveModeChangeNotifies(t *testing.T) {
	rec := NewRecorder("https://mgm")
	listener := &recordingListener{}
	rec.SetConnectionListener(listener)
	if err := rec.AddPeer("peerA", "fqdn", "10.0.0.1"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	waitForCount(t, listener, 1, "initial setListener")

	// Baseline with mode=p2p-dynamic (flip from "" — counted).
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		EffectiveConnectionMode: "p2p-dynamic", LiveOnline: true, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	waitForCount(t, listener, 2, "baseline flip from empty mode")
	listener.peersChangedCount.Store(0)

	// Same mode again — no notification.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		EffectiveConnectionMode: "p2p-dynamic", LiveOnline: true, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), listener.peersChangedCount.Load(),
		"same mode must not fire notification")

	// Mode flip p2p-dynamic → relay-forced — must notify.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		EffectiveConnectionMode: "relay-forced", LiveOnline: true, ServerLivenessKnown: true,
	}); err != nil {
		t.Fatalf("mode flip: %v", err)
	}
	waitForCount(t, listener, 1, "mode flip")
}

// Non-material fields (timeout values, groups, last-seen) MUST NOT fire
// the notification even when they change — they ride the next regular
// 30 s poll and don't need an immediate UI redraw.
func TestStatus_UpdatePeerRemoteMeta_NonMaterialFieldsDoNotNotify(t *testing.T) {
	rec := NewRecorder("https://mgm")
	listener := &recordingListener{}
	rec.SetConnectionListener(listener)
	if err := rec.AddPeer("peerA", "fqdn", "10.0.0.1"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	waitForCount(t, listener, 1, "initial setListener")

	// Baseline.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		LiveOnline: true, ServerLivenessKnown: true,
		EffectiveRelayTimeoutSecs: 60,
		Groups:                    []string{"g1"},
		LastSeenAtServer:          time.Now(),
	}); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	waitForCount(t, listener, 2, "baseline")
	listener.peersChangedCount.Store(0)

	// Change only non-material fields — no notification expected.
	if err := rec.UpdatePeerRemoteMeta("peerA", RemoteMeta{
		LiveOnline: true, ServerLivenessKnown: true,
		EffectiveRelayTimeoutSecs: 90,
		Groups:                    []string{"g1", "g2"},
		LastSeenAtServer:          time.Now(),
	}); err != nil {
		t.Fatalf("non-material change: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	assert.Equal(t, int32(0), listener.peersChangedCount.Load(),
		"non-material field changes must not fire notification")
}
