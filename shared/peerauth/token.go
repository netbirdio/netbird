// Package peerauth authenticates peers to Signal and Relay: Management issues a token bound to
// the peer's keys, and the peer proves possession of its signing key on every connection.
package peerauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AlgoEd25519 is the only token algorithm. It is numbered as the Relay token algorithms, where 1
// is the legacy HMAC token, so a legacy token is never taken for a bound one; the algorithm byte
// leaves room for a post-quantum signature later.
const AlgoEd25519 Algo = 2

const (
	tokenContext = "netbird-peer-auth-token-v1" //nolint:gosec // G101: domain separation label, not a credential

	sizeAlgo    = 1
	sizeKeyID   = 4
	sizeExpiry  = 8
	payloadSize = sizeKeyID + sizeExpiry + wgtypes.KeyLen + ed25519.PublicKeySize
	tokenSize   = sizeAlgo + ed25519.SignatureSize + payloadSize
)

var (
	ErrMalformedToken  = errors.New("malformed token")
	ErrAlgoNotAccepted = errors.New("token algorithm not accepted by this verifier")
	ErrUnknownKeyID    = errors.New("unknown token key id")
	ErrBadTokenSig     = errors.New("invalid token signature")
	ErrTokenExpired    = errors.New("token expired")
	ErrKeyConfig       = errors.New("token verifier needs Management public keys of valid size, each under its derived key ID")
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

// TokenKeys holds the Management public keys a verifier checks tokens with. Verifiers hold no
// secret, so no Relay or Signal can mint a token.
type TokenKeys struct {
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

// IssueEd25519Token signs the token with Management's private key.
func IssueEd25519Token(priv ed25519.PrivateKey, t Token) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key size %d", len(priv))
	}
	t.Algo = AlgoEd25519
	t.KeyID = Ed25519KeyID(priv.Public().(ed25519.PublicKey))
	return issue(t, func(msg []byte) []byte {
		return ed25519.Sign(priv, msg)
	})
}

// KeyIDs returns the IDs of the accepted keys in ascending order, for logging.
func (k TokenKeys) KeyIDs() []KeyID {
	ids := make([]KeyID, 0, len(k.Ed25519))
	for id := range k.Ed25519 {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Validate refuses key material that would make verification panic or never match a token.
func (k TokenKeys) Validate() error {
	if len(k.Ed25519) == 0 {
		return ErrKeyConfig
	}
	for id, pub := range k.Ed25519 {
		if len(pub) != ed25519.PublicKeySize || Ed25519KeyID(pub) != id {
			return ErrKeyConfig
		}
	}
	return nil
}

// VerifyToken checks the token against the verifier keys and its expiry.
func VerifyToken(raw []byte, keys TokenKeys, now time.Time) (*Token, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if len(raw) < sizeAlgo {
		return nil, ErrMalformedToken
	}
	if algo := Algo(raw[0]); algo != AlgoEd25519 {
		return nil, fmt.Errorf("%d: %w", algo, ErrAlgoNotAccepted)
	}
	if len(raw) != tokenSize {
		return nil, ErrMalformedToken
	}

	sig := raw[sizeAlgo : sizeAlgo+ed25519.SignatureSize]
	payload := raw[sizeAlgo+ed25519.SignatureSize:]
	t := parsePayload(payload)

	pub, ok := keys.Ed25519[t.KeyID]
	if !ok {
		return nil, fmt.Errorf("%d: %w", t.KeyID, ErrUnknownKeyID)
	}
	if !ed25519.Verify(pub, tokenSignedMessage(payload), sig) {
		return nil, ErrBadTokenSig
	}
	if !now.Before(t.Expiry) {
		return nil, ErrTokenExpired
	}
	return t, nil
}

func issue(t Token, sign func([]byte) []byte) ([]byte, error) {
	if len(t.AuthPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auth public key size %d", len(t.AuthPub))
	}

	buf := make([]byte, tokenSize)
	buf[0] = byte(t.Algo)
	payload := buf[sizeAlgo+ed25519.SignatureSize:]
	binary.BigEndian.PutUint32(payload, uint32(t.KeyID))
	binary.BigEndian.PutUint64(payload[sizeKeyID:], uint64(t.Expiry.Unix()))
	copy(payload[sizeKeyID+sizeExpiry:], t.WGPub[:])
	copy(payload[sizeKeyID+sizeExpiry+wgtypes.KeyLen:], t.AuthPub)

	copy(buf[sizeAlgo:], sign(tokenSignedMessage(payload)))
	return buf, nil
}

func parsePayload(p []byte) *Token {
	t := &Token{
		Algo:    AlgoEd25519,
		KeyID:   KeyID(binary.BigEndian.Uint32(p)),
		Expiry:  time.Unix(int64(binary.BigEndian.Uint64(p[sizeKeyID:])), 0),
		AuthPub: make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	copy(t.WGPub[:], p[sizeKeyID+sizeExpiry:])
	copy(t.AuthPub, p[sizeKeyID+sizeExpiry+wgtypes.KeyLen:])
	return t
}

func tokenSignedMessage(payload []byte) []byte {
	msg := make([]byte, 0, len(tokenContext)+sizeAlgo+len(payload))
	msg = append(msg, tokenContext...)
	msg = append(msg, byte(AlgoEd25519))
	return append(msg, payload...)
}
