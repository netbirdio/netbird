package rosenpass

import (
	"testing"

	rp "cunicu.li/go-rosenpass"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// handlerTestLink wires two NetbirdHandlers as the two ends of a single
// tunnel: handler A manages the rosenpass peer B and vice versa, the way two
// NetBird clients see each other.
type handlerTestLink struct {
	handlerA, handlerB *NetbirdHandler
	ifaceA, ifaceB     *mockIface
	pidA, pidB         rp.PeerID
	wgKeyA, wgKeyB     wgtypes.Key
}

func newHandlerTestLink(t *testing.T, preSharedKey *[32]byte) *handlerTestLink {
	t.Helper()

	link := &handlerTestLink{
		ifaceA: &mockIface{},
		ifaceB: &mockIface{},
	}
	link.pidA[0] = 0xaa
	link.pidB[0] = 0xbb
	link.wgKeyA[31] = 1
	link.wgKeyB[31] = 2

	link.handlerA = NewNetbirdHandler(preSharedKey, link.wgKeyA)
	link.handlerB = NewNetbirdHandler(preSharedKey, link.wgKeyB)

	link.handlerA.SetInterface(link.ifaceA)
	link.handlerB.SetInterface(link.ifaceB)

	link.handlerA.AddPeer(link.pidB, "wt0", rp.Key(link.wgKeyB))
	link.handlerB.AddPeer(link.pidA, "wt0", rp.Key(link.wgKeyA))

	return link
}

// complete simulates a completed rosenpass exchange: both ends derive the
// same output key.
func (l *handlerTestLink) complete(osk rp.Key) {
	l.handlerA.HandshakeCompleted(l.pidB, osk)
	l.handlerB.HandshakeCompleted(l.pidA, osk)
}

// expire simulates a failed key renewal on both ends.
func (l *handlerTestLink) expire() {
	l.handlerA.HandshakeExpired(l.pidB)
	l.handlerB.HandshakeExpired(l.pidA)
}

func lastPSK(t *testing.T, m *mockIface) wgtypes.Key {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	require.NotEmpty(t, m.calls, "expected at least one SetPresharedKey call")
	return m.calls[len(m.calls)-1].psk
}

func TestHandshakeCompleted_SetsKeyAndInitializes(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	require.Equal(t, wgtypes.Key(osk), lastPSK(t, link.ifaceA), "completed exchange must program the osk")
	require.False(t, link.ifaceA.calls[0].updateOnly, "first rotation must not be update-only")
	require.True(t, link.handlerA.IsPeerInitialized(link.pidB), "peer must be initialized after first completed exchange")

	link.complete(osk)
	require.True(t, link.ifaceA.calls[1].updateOnly, "later rotations must be update-only")
}

// TestHandshakeExpired_BothSidesConverge encodes the core recovery invariant:
// rosenpass renewals run over the tunnel that the PSK itself keys, so when a
// renewal fails on both ends, both ends must fall back to the same key or the
// tunnel can never handshake again.
func TestHandshakeExpired_BothSidesConverge(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	link.expire()
	keyA := lastPSK(t, link.ifaceA)
	keyB := lastPSK(t, link.ifaceB)
	require.NotEqual(t, wgtypes.Key(osk), keyA, "expired key must be rotated out")
	require.Equal(t, keyA, keyB, "both ends must converge on the same key after expiry")

	link.expire()
	require.Equal(t, lastPSK(t, link.ifaceA), lastPSK(t, link.ifaceB),
		"both ends must still converge after repeated expiries")
}

// TestHandshakeExpired_ExpiryWithoutCompletionConverges covers the bootstrap
// case: the initial exchange never completed (the tunnel ran on the rendezvous
// key), so an expiry must not replace the working key with an unrecoverable
// one on either end.
func TestHandshakeExpired_ExpiryWithoutCompletionConverges(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	link.expire()
	require.Equal(t, lastPSK(t, link.ifaceA), lastPSK(t, link.ifaceB),
		"both ends must converge when the exchange never completed")
}

// TestHandshakeExpired_RepeatedExpiryClearsInitialized: once renewals keep
// failing, the peer must drop out of the initialized state so the next
// connection reconfiguration reprograms the rendezvous key instead of
// preserving a poisoned rosenpass-managed key.
func TestHandshakeExpired_RepeatedExpiryClearsInitialized(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	link.expire()
	link.expire()

	require.False(t, link.handlerA.IsPeerInitialized(link.pidB),
		"repeated expiries must clear the initialized state")
	require.False(t, link.handlerB.IsPeerInitialized(link.pidA),
		"repeated expiries must clear the initialized state")
}

// TestHandshakeCompleted_AfterExpiryRecovers: a completed exchange after a
// desync must fully reset the recovery state.
func TestHandshakeCompleted_AfterExpiryRecovers(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk1, osk2 rp.Key
	osk1[0] = 1
	osk2[0] = 2

	link.complete(osk1)
	link.expire()
	link.expire()

	link.complete(osk2)
	require.Equal(t, wgtypes.Key(osk2), lastPSK(t, link.ifaceA), "new exchange must program the fresh osk")
	require.True(t, link.handlerA.IsPeerInitialized(link.pidB), "peer must be initialized again after recovery")

	link.expire()
	require.Equal(t, lastPSK(t, link.ifaceA), lastPSK(t, link.ifaceB),
		"recovered link must converge again on the next expiry")
	require.NotEqual(t, wgtypes.Key(osk2), lastPSK(t, link.ifaceA), "expired key must be rotated out")
}

// TestHandshakeExpired_FirstExpiryRatchetsLastKey: the first expiry must
// derive the replacement from the last shared key, so an attacker who only
// blocks the renewal exchange gains nothing over the previous key.
func TestHandshakeExpired_FirstExpiryRatchetsLastKey(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	link.expire()
	require.Equal(t, RatchetKey(wgtypes.Key(osk)), lastPSK(t, link.ifaceA),
		"first expiry must program the ratcheted key")
	require.True(t, link.handlerA.IsPeerInitialized(link.pidB),
		"ratchet step must keep the peer initialized so reconfigurations preserve the key")
}

// TestHandshakeExpired_RepeatedExpiryFallsBackToSeed: once the ratchet key
// also fails, both ends must land on the same key that peer connections
// program for uninitialized peers, so a reconnect completes the recovery.
func TestHandshakeExpired_RepeatedExpiryFallsBackToSeed(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	link.expire()
	link.expire()

	seed, err := DeterministicSeedKey(link.wgKeyA.String(), link.wgKeyB.String())
	require.NoError(t, err)
	require.Equal(t, *seed, lastPSK(t, link.ifaceA), "repeated expiry must fall back to the seed key")
	require.Equal(t, *seed, lastPSK(t, link.ifaceB), "repeated expiry must fall back to the seed key")
}

// TestHandshakeExpired_ConfiguredPSKUsedAsRendezvous: with an account-level
// preshared key configured, the fallback must be that key, matching what peer
// connections program for uninitialized peers.
func TestHandshakeExpired_ConfiguredPSKUsedAsRendezvous(t *testing.T) {
	psk := &[32]byte{0x77}
	link := newHandlerTestLink(t, psk)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	link.expire()
	link.expire()

	require.Equal(t, wgtypes.Key(*psk), lastPSK(t, link.ifaceA),
		"fallback must be the configured preshared key")
	require.Equal(t, wgtypes.Key(*psk), lastPSK(t, link.ifaceB),
		"fallback must be the configured preshared key on both ends")
}

// TestHandshakeExpired_ExpiryWritesAreUpdateOnly: expiry replacements must
// never create a WireGuard peer that connection management has removed.
func TestHandshakeExpired_ExpiryWritesAreUpdateOnly(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)

	link.expire()
	link.expire()

	for _, call := range link.ifaceA.calls[1:] {
		require.True(t, call.updateOnly, "expiry writes must be update-only")
	}
}

// TestAddPeer_ReAddKeepsRecoveryState: reconnections re-add the peer on every
// OnConnected; that must not reset the expiry chain state.
func TestAddPeer_ReAddKeepsRecoveryState(t *testing.T) {
	link := newHandlerTestLink(t, nil)

	var osk rp.Key
	osk[0] = 0x42
	link.complete(osk)
	link.expire()

	link.handlerA.AddPeer(link.pidB, "wt0", rp.Key(link.wgKeyB))
	require.True(t, link.handlerA.IsPeerInitialized(link.pidB),
		"re-adding a known peer must keep its state")

	link.expire()
	seed, err := DeterministicSeedKey(link.wgKeyA.String(), link.wgKeyB.String())
	require.NoError(t, err)
	require.Equal(t, *seed, lastPSK(t, link.ifaceA),
		"second expiry after re-add must continue to the seed fallback")
}
