// Package pqkem is a spike (NET-1406) for a post-quantum pre-shared-key exchange
// that could replace Rosenpass. It performs an X25519MLKEM768 hybrid key
// encapsulation and derives a 32-byte pre-shared key (PSK).
//
// The exchange is a single round trip designed to ride the (already
// authenticated) Signal offer/answer channel:
//
//	initiator --Offer(1216B)--> responder
//	initiator <--Answer(1120B)-- responder
//
// Both sides then hold the same PSK, which is bound to the two peers' identities
// (their peer identity keys) so the derived key cannot be transplanted
// to a different peer pair even if the transport authentication were bypassed.
//
// Combiner note: this follows the IETF hybrid layout (X25519 ‖ ML-KEM on the
// wire; ML-KEM_ss ‖ X25519_ss into the KDF) from
// draft-kwiatkowski-tls-ecdhe-mlkem. The spike uses SHA-256 as the KDF; a
// production version should use HKDF with the RFC labels — see TODO below.
package pqkem

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	// OfferSize is the initiator message: X25519 public key ‖ ML-KEM-768 encapsulation key.
	OfferSize = 32 + mlkem.EncapsulationKeySize768 // 1216
	// AnswerSize is the responder message: ML-KEM-768 ciphertext ‖ X25519 public key.
	AnswerSize = mlkem.CiphertextSize768 + 32 // 1120

	pskLabel = "netbird-pq-psk-v1"
)

// PSK is the 32-byte derived pre-shared key handed to the consumer to key its channel.
type PSK [32]byte

// Binding identifies the peer pair the PSK is derived for. Callers set both
// peer identity keys; the order does not matter (it is canonicalised).
type Binding struct {
	LocalID  []byte
	RemoteID []byte
}

// Initiator holds the ephemeral secrets between Offer and Finish.
type Initiator struct {
	x25519  *ecdh.PrivateKey
	mlkemDK *mlkem.DecapsulationKey768
	offer   []byte
}

// NewInitiator generates the ephemeral X25519 + ML-KEM-768 keypairs.
func NewInitiator() (*Initiator, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ml-kem keygen: %w", err)
	}

	offer := make([]byte, 0, OfferSize)
	offer = append(offer, x.PublicKey().Bytes()...)
	offer = append(offer, dk.EncapsulationKey().Bytes()...)

	return &Initiator{x25519: x, mlkemDK: dk, offer: offer}, nil
}

// Offer returns the initiator message to send over Signal.
func (i *Initiator) Offer() []byte {
	return i.offer
}

// Finish consumes the responder's answer and derives the PSK.
func (i *Initiator) Finish(answer []byte, b Binding) (PSK, error) {
	if len(answer) != AnswerSize {
		return PSK{}, fmt.Errorf("answer: got %d bytes, want %d", len(answer), AnswerSize)
	}
	ct := answer[:mlkem.CiphertextSize768]
	peerX := answer[mlkem.CiphertextSize768:]

	ssMLKEM, err := i.mlkemDK.Decapsulate(ct)
	if err != nil {
		return PSK{}, fmt.Errorf("ml-kem decapsulate: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerX)
	if err != nil {
		return PSK{}, fmt.Errorf("parse peer x25519: %w", err)
	}
	ssX, err := i.x25519.ECDH(pub)
	if err != nil {
		return PSK{}, fmt.Errorf("x25519 ecdh: %w", err)
	}

	return derivePSK(ssMLKEM, ssX, i.offer, answer, b), nil
}

// Respond consumes an initiator offer, produces the answer, and derives the PSK.
func Respond(offer []byte, b Binding) (answer []byte, psk PSK, err error) {
	if len(offer) != OfferSize {
		return nil, PSK{}, fmt.Errorf("offer: got %d bytes, want %d", len(offer), OfferSize)
	}
	peerX := offer[:32]
	peerEK := offer[32:]

	ek, err := mlkem.NewEncapsulationKey768(peerEK)
	if err != nil {
		return nil, PSK{}, fmt.Errorf("parse peer ml-kem key: %w", err)
	}
	ssMLKEM, ct := ek.Encapsulate()

	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, PSK{}, fmt.Errorf("x25519 keygen: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerX)
	if err != nil {
		return nil, PSK{}, fmt.Errorf("parse peer x25519: %w", err)
	}
	ssX, err := x.ECDH(pub)
	if err != nil {
		return nil, PSK{}, fmt.Errorf("x25519 ecdh: %w", err)
	}

	answer = make([]byte, 0, AnswerSize)
	answer = append(answer, ct...)
	answer = append(answer, x.PublicKey().Bytes()...)

	// derivePSK uses the same argument order on both sides; the responder's local
	// binding is the mirror of the initiator's, canonicalised inside derivePSK.
	return answer, derivePSK(ssMLKEM, ssX, offer, answer, b), nil
}

// derivePSK combines the two shared secrets and binds the result to the full
// transcript (offer ‖ answer) and the canonicalised peer identities.
//
// TODO(NET-1406): replace the SHA-256 concat with the RFC HKDF combiner
// (crypto/hkdf, Go 1.24+) and proper labels before this leaves spike status.
func derivePSK(ssMLKEM, ssX, offer, answer []byte, b Binding) PSK {
	lo, hi := canonicalPair(b.LocalID, b.RemoteID)

	h := sha256.New()
	h.Write([]byte(pskLabel))
	h.Write(ssMLKEM)
	h.Write(ssX)
	h.Write(offer)
	h.Write(answer)
	h.Write(lo)
	h.Write(hi)

	var psk PSK
	copy(psk[:], h.Sum(nil))
	return psk
}

func canonicalPair(a, b []byte) (lo, hi []byte) {
	if string(a) <= string(b) {
		return a, b
	}
	return b, a
}
