package certproof

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

// errPINRejectedBefore is returned instead of logging in with a PIN the token already
// refused: every failed login counts towards the token's lockout, which for a TPM is
// shared with everything else on the machine, and proofs are collected on every sync.
var errPINRejectedBefore = errors.New("PKCS#11 token rejected this PIN before, not trying it again")

// rejectedPINs outlives a single store, since a store is built for each collection.
var rejectedPINs = &pinLatch{keys: map[[sha256.Size]byte]struct{}{}}

// pinLatch remembers PINs a token rejected. Keys are hashes, so the PIN itself is not
// kept in memory any longer than the store that read it.
type pinLatch struct {
	mu   sync.Mutex
	keys map[[sha256.Size]byte]struct{}
}

func (l *pinLatch) has(key [sha256.Size]byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.keys[key]
	return ok
}

func (l *pinLatch) add(key [sha256.Size]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys[key] = struct{}{}
}

// rejectedPINKey identifies a PIN for one token of one module, so a PIN another token
// rejected is still tried on the token it belongs to.
func rejectedPINKey(module, token string, pin []byte) [sha256.Size]byte {
	var buf []byte
	for _, part := range [][]byte{[]byte(module), []byte(token), pin} {
		buf = binary.BigEndian.AppendUint64(buf, uint64(len(part)))
		buf = append(buf, part...)
	}
	return sha256.Sum256(buf)
}
