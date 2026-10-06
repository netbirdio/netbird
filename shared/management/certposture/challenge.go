package certposture

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	Window = 12 * time.Hour

	challengeDomain = "netbird-cert-challenge-v1"
	windowLen       = 8
	nonceLen        = windowLen + sha256.Size

	// NonceSize is the length of every nonce a Challenger issues.
	NonceSize = nonceLen
)

var (
	ErrNonceMalformed = errors.New("certificate challenge nonce is malformed")
	ErrNonceExpired   = errors.New("certificate challenge nonce is expired")
	ErrNonceMismatch  = errors.New("certificate challenge nonce was not issued to this peer")
)

// Challenger issues and verifies stateless per-peer nonces. A nonce is bound to the
// peer and to a time window, so any instance sharing the secret can verify it.
type Challenger struct {
	secret []byte
	window time.Duration
}

func NewChallenger(secret []byte) *Challenger {
	return &Challenger{secret: secret, window: Window}
}

func (c *Challenger) Nonce(peerKey []byte, now time.Time) []byte {
	return c.nonceForWindow(peerKey, c.windowOf(now))
}

func (c *Challenger) verifyNonce(nonce, peerKey []byte, now time.Time) error {
	if len(nonce) != nonceLen {
		return ErrNonceMalformed
	}
	window := binary.BigEndian.Uint64(nonce[:windowLen])
	current := c.windowOf(now)
	if window != current && window+1 != current {
		return ErrNonceExpired
	}
	if !hmac.Equal(nonce, c.nonceForWindow(peerKey, window)) {
		return ErrNonceMismatch
	}
	return nil
}

func (c *Challenger) windowOf(now time.Time) uint64 {
	return uint64(now.Unix() / int64(c.window.Seconds()))
}

func (c *Challenger) nonceForWindow(peerKey []byte, window uint64) []byte {
	nonce := make([]byte, windowLen, nonceLen)
	binary.BigEndian.PutUint64(nonce, window)

	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(challengeDomain))
	mac.Write(peerKey)
	mac.Write(nonce[:windowLen])
	return mac.Sum(nonce)
}

// NonceAcceptedAlongside reports whether a proof answering nonce is still accepted while
// management issues current to the same peer: verification takes a nonce of the current
// or the previous window.
func NonceAcceptedAlongside(nonce, current []byte) bool {
	if len(nonce) != nonceLen || len(current) != nonceLen {
		return false
	}
	window := binary.BigEndian.Uint64(nonce[:windowLen])
	currentWindow := binary.BigEndian.Uint64(current[:windowLen])
	return window == currentWindow || window+1 == currentWindow
}
