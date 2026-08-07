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
// Combiner note: this follows draft-ietf-tls-ecdhe-mlkem for X25519MLKEM768 — on
// the wire ML-KEM ‖ X25519 (the draft deliberately reversed the share order for
// this group), and ML-KEM_ss ‖ X25519_ss as the KDF input. The PSK is derived with
// HKDF-SHA256 over that hybrid secret, salted with a domain-separation label and
// bound (via the HKDF info) to the full transcript and the canonicalised peer
// identities.
package pqkem

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	// OfferSize is the initiator message: ML-KEM-768 encapsulation key ‖ X25519 public key
	// (share order per draft-ietf-tls-ecdhe-mlkem for X25519MLKEM768).
	OfferSize = mlkem.EncapsulationKeySize768 + 32 // 1216
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
	offer = append(offer, dk.EncapsulationKey().Bytes()...)
	offer = append(offer, x.PublicKey().Bytes()...)

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

	return derivePSK(ssMLKEM, ssX, i.offer, answer, b)
}

// Respond consumes an initiator offer, produces the answer, and derives the PSK.
func Respond(offer []byte, b Binding) (answer []byte, psk PSK, err error) {
	if len(offer) != OfferSize {
		return nil, PSK{}, fmt.Errorf("offer: got %d bytes, want %d", len(offer), OfferSize)
	}
	peerEK := offer[:mlkem.EncapsulationKeySize768]
	peerX := offer[mlkem.EncapsulationKeySize768:]

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
	psk, err = derivePSK(ssMLKEM, ssX, offer, answer, b)
	if err != nil {
		return nil, PSK{}, err
	}
	return answer, psk, nil
}

// derivePSK runs HKDF-SHA256 over the hybrid shared secret (ML-KEM_ss ‖ X25519_ss,
// per draft-ietf-tls-ecdhe-mlkem), salted with the domain-separation label, and binds
// the result — via the HKDF info — to the full transcript (offer ‖ answer) and the
// canonicalised peer identities, so the PSK cannot be transplanted to another peer
// pair or a different exchange.
func derivePSK(ssMLKEM, ssX, offer, answer []byte, b Binding) (PSK, error) {
	// A PSK not bound to both peer identities could be transplanted to a different peer
	// pair, so refuse to derive one from an empty binding.
	if len(b.LocalID) == 0 || len(b.RemoteID) == 0 {
		return PSK{}, fmt.Errorf("empty peer identity binding")
	}
	lo, hi := canonicalPair(b.LocalID, b.RemoteID)

	ikm := make([]byte, 0, len(ssMLKEM)+len(ssX))
	ikm = append(ikm, ssMLKEM...)
	ikm = append(ikm, ssX...)

	info := make([]byte, 0, len(offer)+len(answer)+len(lo)+len(hi))
	info = append(info, offer...)
	info = append(info, answer...)
	info = append(info, lo...)
	info = append(info, hi...)

	var psk PSK
	key, err := hkdf.Key(sha256.New, ikm, []byte(pskLabel), string(info), len(psk))
	if err != nil {
		return PSK{}, fmt.Errorf("hkdf derive psk: %w", err)
	}
	copy(psk[:], key)
	return psk, nil
}

func canonicalPair(a, b []byte) (lo, hi []byte) {
	if string(a) <= string(b) {
		return a, b
	}
	return b, a
}
