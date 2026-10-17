package pqkem

import (
	"crypto/mlkem"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExchange_TamperedCiphertextFailsClosed verifies the core fail-closed
// property: mutating the ML-KEM ciphertext in the answer does not error (ML-KEM
// uses implicit rejection — Decapsulate always returns a value) but yields a
// different shared secret, so the initiator derives a PSK that does NOT match the
// responder's. A mismatched PSK means WireGuard passes no bytes: tamper => no data.
func TestExchange_TamperedCiphertextFailsClosed(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	answer, pskB, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	tampered := append([]byte(nil), answer...)
	tampered[0] ^= 0xff // flip a bit in the ML-KEM ciphertext

	pskA, err := init.Finish(tampered, Binding{LocalID: wgA, RemoteID: wgB})
	require.NoError(t, err, "implicit rejection: decapsulate still succeeds")
	require.NotEqual(t, pskB, pskA, "tampered ciphertext must not yield the responder's PSK")
}

// TestExchange_TamperedX25519ShareDiverges flips a byte in the answer's X25519
// share: the classical half of the hybrid secret changes, so the derived PSK
// diverges from the responder's (fail-closed on the ECDH half too).
func TestExchange_TamperedX25519ShareDiverges(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	answer, pskB, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	tampered := append([]byte(nil), answer...)
	tampered[mlkem.CiphertextSize768] ^= 0x01 // first byte of the X25519 public key

	pskA, err := init.Finish(tampered, Binding{LocalID: wgA, RemoteID: wgB})
	// Either the point is rejected (error) or the ECDH differs (different PSK);
	// in both cases the honest PSK is never reproduced.
	if err == nil {
		require.NotEqual(t, pskB, pskA, "tampered X25519 share must not yield the responder's PSK")
	}
}

// TestExchange_AllZeroX25519Rejected feeds an all-zero X25519 share (a low-order
// point) in the answer. The stdlib ECDH must reject it, so Finish errors rather
// than deriving a PSK from a degenerate secret.
func TestExchange_AllZeroX25519Rejected(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	answer, _, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	bad := append([]byte(nil), answer...)
	for i := mlkem.CiphertextSize768; i < len(bad); i++ {
		bad[i] = 0
	}

	_, err = init.Finish(bad, Binding{LocalID: wgA, RemoteID: wgB})
	require.Error(t, err, "all-zero X25519 share (low-order point) must be rejected")
}

// TestExchange_SizeBoundaries locks the exact-length framing checks: one byte
// short or long on either message is rejected, not silently truncated/padded.
func TestExchange_SizeBoundaries(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)
	offer := init.Offer()

	_, _, err = Respond(offer[:OfferSize-1], Binding{})
	require.Error(t, err, "offer one byte short")
	_, _, err = Respond(append(append([]byte(nil), offer...), 0), Binding{})
	require.Error(t, err, "offer one byte long")

	answer, _, err := Respond(offer, Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	_, err = init.Finish(answer[:AnswerSize-1], Binding{LocalID: wgA, RemoteID: wgB})
	require.Error(t, err, "answer one byte short")
	_, err = init.Finish(append(append([]byte(nil), answer...), 0), Binding{LocalID: wgA, RemoteID: wgB})
	require.Error(t, err, "answer one byte long")
}

// TestExchange_BindingIsSymmetric confirms the canonicalisation: the two peers
// pass their identities in opposite (Local, Remote) order yet derive the same PSK,
// so identity binding does not depend on who is initiator vs responder.
func TestExchange_BindingIsSymmetric(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	answer, pskB, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	pskA, err := init.Finish(answer, Binding{LocalID: wgA, RemoteID: wgB})
	require.NoError(t, err)

	require.Equal(t, pskB, pskA, "swapped Local/Remote order must canonicalise to the same PSK")
}
