// Package peerauth authenticates peers to Signal and Relay: Management issues a token bound to
// the peer's keys, and the peer proves possession of its signing key on every connection.
package peerauth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Token algorithms, numbered as the Relay token algorithms. The bytes the MAC or signature
// covers differ from the legacy Relay token, so a legacy Relay rejects these tokens.
const (
	AlgoHMACSHA256 Algo = 1
	AlgoEd25519    Algo = 2
)

const (
	tokenContext = "netbird-peer-auth-token-v1" //nolint:gosec // G101: domain separation label, not a credential

	sizeAlgo    = 1
	sizeKeyID   = 4
	sizeExpiry  = 8
	payloadSize = sizeKeyID + sizeExpiry + wgtypes.KeyLen + ed25519.PublicKeySize

	minHMACSecretSize = sha256.Size

	// HMACKeyID is the key ID of HMAC tokens: there is a single secret and it is never rotated.
	HMACKeyID KeyID = 0
)

var (
	ErrMalformedToken  = errors.New("malformed token")
	ErrAlgoNotAccepted = errors.New("token algorithm not accepted by this verifier")
	ErrUnknownKeyID    = errors.New("unknown token key id")
	ErrBadTokenSig     = errors.New("invalid token signature")
	ErrTokenExpired    = errors.New("token expired")
	ErrKeyConfig       = errors.New("exactly one of an HMAC secret and Ed25519 keys must be set, with valid sizes and key IDs")
)

// Algo is the algorithm Management signs the token with.
type Algo byte

// KeyID identifies the Management key that signed a token. It is derived from the Ed25519 public
// key, so verifiers pick the key without configuring IDs and rotated keys never share one.
type KeyID uint32

// Token is the content Management vouches for: the peer's WireGuard key and its signing key.
type Token struct {
	Algo    Algo
	KeyID   KeyID
	Expiry  time.Time
	WGPub   wgtypes.Key
	AuthPub ed25519.PublicKey
}

// TokenKeys holds what a verifier checks tokens with. HMAC and Ed25519 are mutually exclusive:
// a verifier configured for Ed25519 never accepts an HMAC token, so a leaked secret cannot
// downgrade it.
type TokenKeys struct {
	HMAC []byte
	// Ed25519 maps each accepted Management public key by its Ed25519KeyID; build it with
	// NewEd25519Keys.
	Ed25519 map[KeyID]ed25519.PublicKey
}

// Ed25519KeyID derives the key ID of a Management public key from its SHA-256 digest.
func Ed25519KeyID(pub ed25519.PublicKey) KeyID {
	sum := sha256.Sum256(pub)
	return KeyID(binary.BigEndian.Uint32(sum[:]))
}

// NewEd25519Keys returns verifier keys accepting tokens signed by any of the given Management
// public keys, refusing keys of the wrong size and keys whose IDs collide.
func NewEd25519Keys(pubs []ed25519.PublicKey) (TokenKeys, error) {
	keys := make(map[KeyID]ed25519.PublicKey, len(pubs))
	for _, pub := range pubs {
		if len(pub) != ed25519.PublicKeySize {
			return TokenKeys{}, fmt.Errorf("public key size %d: %w", len(pub), ErrKeyConfig)
		}
		id := Ed25519KeyID(pub)
		if _, ok := keys[id]; ok {
			return TokenKeys{}, fmt.Errorf("duplicate or colliding public key, key id %d: %w", id, ErrKeyConfig)
		}
		keys[id] = pub
	}
	return TokenKeys{Ed25519: keys}, nil
}

// IssueHMACToken signs the token with a secret shared between Management, Signal and Relay.
func IssueHMACToken(secret []byte, t Token) ([]byte, error) {
	t.Algo = AlgoHMACSHA256
	t.KeyID = HMACKeyID
	return issue(t, sha256.Size, func(msg []byte) []byte {
		h := hmac.New(sha256.New, secret)
		h.Write(msg)
		return h.Sum(nil)
	})
}

// IssueEd25519Token signs the token with Management's private key.
func IssueEd25519Token(priv ed25519.PrivateKey, t Token) ([]byte, error) {
	t.Algo = AlgoEd25519
	t.KeyID = Ed25519KeyID(priv.Public().(ed25519.PublicKey))
	return issue(t, ed25519.SignatureSize, func(msg []byte) []byte {
		return ed25519.Sign(priv, msg)
	})
}

// Mode returns the only algorithm the keys accept, refusing key material that would make
// tokens forgeable or verification panic.
func (k TokenKeys) Mode() (Algo, error) {
	switch {
	case len(k.HMAC) > 0 && len(k.Ed25519) == 0:
		if len(k.HMAC) < minHMACSecretSize {
			return 0, ErrKeyConfig
		}
		return AlgoHMACSHA256, nil
	case len(k.Ed25519) > 0 && len(k.HMAC) == 0:
		for id, pub := range k.Ed25519 {
			if len(pub) != ed25519.PublicKeySize || Ed25519KeyID(pub) != id {
				return 0, ErrKeyConfig
			}
		}
		return AlgoEd25519, nil
	default:
		return 0, ErrKeyConfig
	}
}

// VerifyToken checks the token against the verifier keys and its expiry.
func VerifyToken(raw []byte, keys TokenKeys, now time.Time) (*Token, error) {
	mode, err := keys.Mode()
	if err != nil {
		return nil, err
	}
	if len(raw) < sizeAlgo {
		return nil, ErrMalformedToken
	}
	if algo := Algo(raw[0]); algo != mode {
		return nil, fmt.Errorf("%d: %w", algo, ErrAlgoNotAccepted)
	}
	if len(raw) != sizeAlgo+mode.sigSize()+payloadSize {
		return nil, ErrMalformedToken
	}

	sig := raw[sizeAlgo : sizeAlgo+mode.sigSize()]
	payload := raw[sizeAlgo+mode.sigSize():]
	t := parsePayload(mode, payload)
	msg := tokenSignedMessage(mode, payload)

	if err := keys.verify(t.KeyID, msg, sig); err != nil {
		return nil, err
	}
	if !now.Before(t.Expiry) {
		return nil, ErrTokenExpired
	}
	return t, nil
}

func (k TokenKeys) verify(id KeyID, msg, sig []byte) error {
	if len(k.HMAC) > 0 && id == HMACKeyID {
		h := hmac.New(sha256.New, k.HMAC)
		h.Write(msg)
		if !hmac.Equal(h.Sum(nil), sig) {
			return ErrBadTokenSig
		}
		return nil
	}
	if pub, ok := k.Ed25519[id]; ok {
		if !ed25519.Verify(pub, msg, sig) {
			return ErrBadTokenSig
		}
		return nil
	}
	return fmt.Errorf("%d: %w", id, ErrUnknownKeyID)
}

func (a Algo) sigSize() int {
	if a == AlgoEd25519 {
		return ed25519.SignatureSize
	}
	return sha256.Size
}

func issue(t Token, sigSize int, sign func([]byte) []byte) ([]byte, error) {
	if len(t.AuthPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth public key size %d", len(t.AuthPub))
	}

	buf := make([]byte, sizeAlgo+sigSize+payloadSize)
	buf[0] = byte(t.Algo)
	payload := buf[sizeAlgo+sigSize:]
	binary.BigEndian.PutUint32(payload, uint32(t.KeyID))
	binary.BigEndian.PutUint64(payload[sizeKeyID:], uint64(t.Expiry.Unix()))
	copy(payload[sizeKeyID+sizeExpiry:], t.WGPub[:])
	copy(payload[sizeKeyID+sizeExpiry+wgtypes.KeyLen:], t.AuthPub)

	copy(buf[sizeAlgo:], sign(tokenSignedMessage(t.Algo, payload)))
	return buf, nil
}

func parsePayload(algo Algo, p []byte) *Token {
	t := &Token{
		Algo:    algo,
		KeyID:   KeyID(binary.BigEndian.Uint32(p)),
		Expiry:  time.Unix(int64(binary.BigEndian.Uint64(p[sizeKeyID:])), 0),
		AuthPub: make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	copy(t.WGPub[:], p[sizeKeyID+sizeExpiry:])
	copy(t.AuthPub, p[sizeKeyID+sizeExpiry+wgtypes.KeyLen:])
	return t
}

func tokenSignedMessage(algo Algo, payload []byte) []byte {
	msg := make([]byte, 0, len(tokenContext)+sizeAlgo+len(payload))
	msg = append(msg, tokenContext...)
	msg = append(msg, byte(algo))
	return append(msg, payload...)
}
