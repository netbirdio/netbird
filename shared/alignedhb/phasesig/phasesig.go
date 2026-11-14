// Package phasesig derives the aligned heartbeat phase of a peer and signs it.
//
// Management computes the phase and signs it. Signal and relay only check the
// signature, so a client cannot hand them a phase of its own choice. All three
// derive their keys from one secret they share, the relay auth secret.
//
// The phase is HMAC-SHA256(phaseKey, peerID || day) mod period, with day the
// unix day of the server clock. It is the same on every Management instance
// and after a restart, and changes once a day. The signature is
// HMAC-SHA256(signatureKey, peerID || period || phase || day).
//
// peerID is the relay form of the peer public key (messages.HashID), the only
// form the relay server knows.
package phasesig

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	// SignatureSize is the size of a phase signature.
	SignatureSize = sha256.Size
	// DayTolerance is how many days before or after its own day a signed phase
	// is accepted. It covers the day change and a Management outage, during
	// which the client keeps sending its last signed phase.
	DayTolerance = 1

	keySize       = 32
	secondsPerDay = 24 * 60 * 60

	// The HKDF info strings keep the two keys apart from each other and from
	// any other key derived from the same secret.
	infoPhase     = "netbird-aligned-heartbeat-phase-v1"
	infoSignature = "netbird-aligned-heartbeat-signature-v1"
)

var (
	// ErrNoSecret is returned when no non-empty secret is configured.
	ErrNoSecret = errors.New("no aligned heartbeat secret")
	// ErrBadSignature is returned when no configured key produced the signature.
	ErrBadSignature = errors.New("bad phase signature")
	// ErrDayOutOfRange is returned when the signed day is too far from today.
	ErrDayOutOfRange = errors.New("signed day out of range")
	// ErrInvalidPhase is returned when the phase or period cannot be signed.
	ErrInvalidPhase = errors.New("invalid phase or period")
)

type keySet struct {
	phase     []byte
	signature []byte
}

// Signer computes and signs phases. Management uses it.
type Signer struct {
	keys keySet
}

// Verifier checks phase signatures. Signal and relay use it.
type Verifier struct {
	keys []keySet
}

// Day returns the unix day of t, the day that goes into the phase.
func Day(t time.Time) int64 {
	s := t.Unix()
	d := s / secondsPerDay
	if s%secondsPerDay < 0 {
		d--
	}
	return d
}

// NewSigner returns a signer with keys derived from secret.
func NewSigner(secret string) (*Signer, error) {
	keys, err := deriveKeys(secret)
	if err != nil {
		return nil, err
	}
	return &Signer{keys: keys}, nil
}

// Phase returns the phase of peer on day for period. period must be at least
// one millisecond, else the phase is zero.
func (s *Signer) Phase(peer messages.PeerID, period time.Duration, day int64) time.Duration {
	p := period.Milliseconds()
	if p < 1 {
		return 0
	}
	mac := hmac.New(sha256.New, s.keys.phase)
	mac.Write(peer[:])
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(day)))
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint64(sum[:8])
	return time.Duration(n%uint64(p)) * time.Millisecond
}

// SignedPhase returns the phase of peer for period on the day of now, with its
// signature.
func (s *Signer) SignedPhase(peer messages.PeerID, period time.Duration, now time.Time) (alignedhb.SignedPhase, error) {
	day := Day(now)
	phase := s.Phase(peer, period, day)
	msg, err := signedMessage(peer, period, phase, day)
	if err != nil {
		return alignedhb.SignedPhase{}, err
	}
	return alignedhb.SignedPhase{
		Phase:     phase,
		Day:       day,
		Signature: sign(s.keys.signature, msg),
	}, nil
}

// NewVerifier returns a verifier that accepts a signature made with any of
// secrets. Passing the old and the new secret during a rotation keeps the
// phases of both valid. Empty secrets are skipped. At least one non-empty
// secret is required.
func NewVerifier(secrets ...string) (*Verifier, error) {
	var keys []keySet
	var seen []string
	for _, secret := range secrets {
		if secret == "" || slices.Contains(seen, secret) {
			continue
		}
		seen = append(seen, secret)
		k, err := deriveKeys(secret)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, ErrNoSecret
	}
	return &Verifier{keys: keys}, nil
}

// Verify reports whether sp was signed by Management for peer and period, on a
// day at most DayTolerance away from the day of now.
func (v *Verifier) Verify(peer messages.PeerID, period time.Duration, sp alignedhb.SignedPhase, now time.Time) error {
	if diff := Day(now) - sp.Day; diff > DayTolerance || diff < -DayTolerance {
		return fmt.Errorf("day %d, today %d: %w", sp.Day, Day(now), ErrDayOutOfRange)
	}
	if len(sp.Signature) != SignatureSize {
		return fmt.Errorf("signature length %d: %w", len(sp.Signature), ErrBadSignature)
	}
	msg, err := signedMessage(peer, period, sp.Phase, sp.Day)
	if err != nil {
		return err
	}
	for _, k := range v.keys {
		if hmac.Equal(sign(k.signature, msg), sp.Signature) {
			return nil
		}
	}
	return ErrBadSignature
}

func deriveKeys(secret string) (keySet, error) {
	if secret == "" {
		return keySet{}, ErrNoSecret
	}
	phase, err := hkdf.Key(sha256.New, []byte(secret), nil, infoPhase, keySize)
	if err != nil {
		return keySet{}, fmt.Errorf("derive phase key: %w", err)
	}
	signature, err := hkdf.Key(sha256.New, []byte(secret), nil, infoSignature, keySize)
	if err != nil {
		return keySet{}, fmt.Errorf("derive signature key: %w", err)
	}
	return keySet{phase: phase, signature: signature}, nil
}

// signedMessage encodes peer || period seconds (uint32) || phase ms (uint32) ||
// day (int64), integers big endian.
func signedMessage(peer messages.PeerID, period, phase time.Duration, day int64) ([]byte, error) {
	if period < time.Second || period%time.Second != 0 || period/time.Second > 1<<32-1 {
		return nil, fmt.Errorf("period %s: %w", period, ErrInvalidPhase)
	}
	if !alignedhb.ValidPhase(phase, period) {
		return nil, fmt.Errorf("phase %s for period %s: %w", phase, period, ErrInvalidPhase)
	}
	msg := make([]byte, 0, len(peer)+4+4+8)
	msg = append(msg, peer[:]...)
	msg = binary.BigEndian.AppendUint32(msg, uint32(period/time.Second))
	msg = binary.BigEndian.AppendUint32(msg, uint32(phase.Milliseconds()))
	msg = binary.BigEndian.AppendUint64(msg, uint64(day))
	return msg, nil
}

func sign(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}
