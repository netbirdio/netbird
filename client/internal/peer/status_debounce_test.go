package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Codex hardening: while the engine is in the offline-debounce
// window, the per-peer Status must remain consistent with the
// daemon's actual local connection state. Specifically: if the local
// conn is still alive (no Close() yet), peer status must NOT
// prematurely flip to Idle/Disconnected just because liveness flipped
// false.

func TestStatus_DuringOfflineDebounce_LocalConnStateUnchanged(t *testing.T) {
	key := "test-peer-key"
	ip := "10.10.10.10"
	fqdn := "peer.example.local"
	rec := NewRecorder("https://mgm")
	if err := rec.AddPeer(key, fqdn, ip); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	// Simulate: peer is connected via P2P, mgmt told us peer is live.
	rec.UpdatePeerICEState(State{
		PubKey:                     key,
		ConnStatus:                 StatusConnected,
		ConnStatusUpdate:           time.Now(),
		Relayed:                    false,
		LocalIceCandidateType:      "host",
		RemoteIceCandidateType:     "host",
		LocalIceCandidateEndpoint:  "192.168.91.154:51820",
		RemoteIceCandidateEndpoint: "192.168.91.103:51820",
	})
	rec.UpdatePeerRemoteMeta(key, RemoteMeta{
		LiveOnline:          true,
		ServerLivenessKnown: true,
	})

	state, err := rec.GetPeer(key)
	assert.NoError(t, err)
	assert.Equal(t, StatusConnected, state.ConnStatus, "baseline: must be Connected")
	assert.False(t, state.Relayed, "baseline: must be P2P (not relayed)")
	assert.True(t, state.RemoteLiveOnline, "baseline: must be live")

	// Mgmt push: peer flipped to live=false. Status recorder MUST keep
	// reporting the local conn as Connected/P2P -- the engine's
	// debounce timer is what closes the conn (after 5 s grace),
	// not the StatusRecorder. Until conn.Close fires, the daemon
	// should answer status queries with the still-live transport.
	rec.UpdatePeerRemoteMeta(key, RemoteMeta{
		LiveOnline:          false,
		ServerLivenessKnown: true,
	})

	state, err = rec.GetPeer(key)
	assert.NoError(t, err)
	assert.Equal(t, StatusConnected, state.ConnStatus, "during debounce: ConnStatus must remain Connected")
	assert.False(t, state.Relayed, "during debounce: Relayed must remain false")
	assert.False(t, state.RemoteLiveOnline, "during debounce: liveness must reflect mgmt update")
	assert.True(t, state.RemoteServerLivenessKnown, "during debounce: livenessKnown stays true")
}

// After the engine actually closes the conn (e.g. debounce expired),
// the per-peer status should reflect the local-conn-closed state.
// The transition from Connected->Idle is driven by Conn.Close calling
// setStatusToDisconnected which calls UpdatePeerState(StatusIdle).
func TestStatus_AfterDebouncedClose_StatusReflectsLocalIdle(t *testing.T) {
	key := "test-peer-key"
	ip := "10.10.10.10"
	fqdn := "peer.example.local"
	rec := NewRecorder("https://mgm")
	if err := rec.AddPeer(key, fqdn, ip); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	// Connected state.
	rec.UpdatePeerICEState(State{
		PubKey:           key,
		ConnStatus:       StatusConnected,
		ConnStatusUpdate: time.Now(),
		Relayed:          false,
	})

	// Engine: debounce expired, conn.Close fired, status flips Idle.
	rec.UpdatePeerState(State{
		PubKey:           key,
		ConnStatus:       StatusIdle,
		ConnStatusUpdate: time.Now(),
	})

	state, err := rec.GetPeer(key)
	assert.NoError(t, err)
	assert.Equal(t, StatusIdle, state.ConnStatus, "after debounced close: status must be Idle")
}

// Codex hardening: ConnectionTypeExtended derive must reflect the
// CURRENT live state, not transient debounce states. While peer is
// Connected via P2P and mgmt flips liveness false, the derived label
// should still report "P2P" -- the connection IS still working
// locally. Only when ConnStatus flips to Idle does the label clear.
func TestStatus_DeriveExtended_DuringLivenessFlap(t *testing.T) {
	state := State{
		ConnStatus:                StatusConnected,
		Relayed:                   false,
		RemoteLiveOnline:          true,
		RemoteServerLivenessKnown: true,
	}
	assert.Equal(t, "P2P", DeriveConnectionTypeExtended(state), "P2P with full live")

	// Liveness flips false (debounce in flight).
	state.RemoteLiveOnline = false
	assert.Equal(t, "P2P", DeriveConnectionTypeExtended(state), "P2P remains during liveness flip — local conn still works")

	// Eventually conn closes → ConnStatus Idle.
	state.ConnStatus = StatusIdle
	assert.Equal(t, "", DeriveConnectionTypeExtended(state), "Idle clears the label")
}

// Status proto round-trip: new effective + ICE-backoff fields must
// survive ToProto without loss.
func TestStatus_GetFullStatus_PreservesEffectiveAndBackoffFields(t *testing.T) {
	key := "p1"
	rec := NewRecorder("https://mgm")
	_ = rec.AddPeer(key, "p1.example", "10.10.10.10")

	rec.UpdatePeerICEState(State{
		PubKey:           key,
		ConnStatus:       StatusConnected,
		ConnStatusUpdate: time.Now(),
		Relayed:          true,
	})
	rec.UpdatePeerRemoteMeta(key, RemoteMeta{
		EffectiveConnectionMode:   "p2p-dynamic",
		EffectiveRelayTimeoutSecs: 86400,
		EffectiveP2PTimeoutSecs:   10800,
		EffectiveP2PRetryMaxSecs:  900,
	})

	full := rec.GetFullStatus()
	assert.Len(t, full.Peers, 1)
	p := full.Peers[0]
	assert.Equal(t, "p2p-dynamic", p.RemoteEffectiveConnectionMode)
	assert.Equal(t, uint32(86400), p.RemoteEffectiveRelayTimeoutSecs)
	assert.Equal(t, uint32(10800), p.RemoteEffectiveP2PTimeoutSecs)
	assert.Equal(t, uint32(900), p.RemoteEffectiveP2PRetryMaxSecs)
}
